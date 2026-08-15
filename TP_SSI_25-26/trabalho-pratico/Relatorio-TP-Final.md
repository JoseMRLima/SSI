# Relatório do Trabalho Prático: Sistema de Chat Seguro com E2EE e PKI
**Disciplina:** Segurança de Sistemas Informáticos
**Data Limite de Entrega:** 24 de Maio de 2026

---

## 1. Descrição Detalhada da Arquitetura, Fluxos de Comunicação e Funcionalidades

### 1.1. Modelo Arquitetural da Solução
A solução desenvolvida adota um modelo arquitetural cliente-servidor assíncrono e multi-threaded, estabelecido sobre conexões de sockets TCP na camada de transporte. A separação lógica entre as duas entidades assegura o cumprimento estrito dos requisitos funcionais, operando de forma autónoma em instâncias distintas:

* **Servidor (`server.py`):** Atua como um ponto centralizado de coordenação, roteamento e persistência. O servidor opera em loop contínuo, gerando uma nova thread dedicada para cada cliente que estabelece conexão. É responsável por gerir o estado de utilizadores online, intermediar a troca de chaves, reencaminhar mensagens e assegurar o armazenamento seguro de metadados e mensagens em falta através de um arquivo de persistência em disco denominado `utilizadores.json`.
* **Cliente (`client.py`):** Consiste numa aplicação interativa baseada num interpretador de comandos em modo texto. Para garantir a capacidade de receção concorrente de dados enquanto o utilizador introduz comandos na linha de comandos, o cliente subdivide-se em duas threads principais: a thread de interface/comando (Main Thread) e a thread de escuta em segundo plano (Receiver Thread), que monitoriza o socket continuamente à procura de payloads transmitidos pelo servidor.

A comunicação de dados estruturados entre cliente e servidor é padronizada através da serialização de objetos digitais em formato JSON. De forma a contornar o problema de fragmentação ou junção de pacotes inerente à natureza de fluxo contínuo do protocolo TCP, foi implementada uma camada de encapsulamento (Framing) no módulo `crypto_utils.py`. Cada mensagem é obrigatoriamente precedida por um cabeçalho fixo de 4 bytes codificado em formato *big-endian*, o qual especifica o tamanho exato em bytes do payload estruturado que se segue. O sistema valida sanitariamente este cabeçalho contra um limite estrito de 10 MB (`MAX_MSG_SIZE`), rejeitando imediatamente conexões maliciosas que tentem provocar falhas de alocação de memória.

### 1.2. Metodologia de Gestão de Chaves
O princípio fundamental do sistema é a descentralização do material criptográfico crítico, garantindo que o servidor nunca tenha acesso a dados em plaintext. A topologia de chaves assenta em três pilares distintos:

1.  **Chaves de Identidade Criptográfica (Longa Duração):** Cada utilizador cria a sua identidade digital única através de um par de chaves assimétricas baseadas no algoritmo **Ed25519**. A chave privada é guardada de forma segura na máquina local do utilizador (`<username>.key`), cifrada em repouso com uma password fornecida pelo utilizador (usando `BestAvailableEncryption` da biblioteca `cryptography`, que aplica AES-256-CBC com PBKDF2 internamente), sem nunca transitar pela rede. A chave pública correspondente é enviada ao servidor durante a fase de registo para efeitos de validação de identidade e emissão de certificados.
2.  **Chaves de Acordo de Sessão (Efémeras):** Para o estabelecimento de uma sessão de conversação ponta-a-ponta (E2E), os clientes geram chaves assimétricas efémeras utilizando a curva elíptica **X25519**. Estas chaves são dinâmicas, geradas exclusivamente no momento em que um pedido de chat é iniciado e descartadas imediatamente após a conclusão do aperto de mão criptográfico.
3.  **Chaves Simétricas de Cifragem de Fluxo:** O segredo partilhado bruto resultante do protocolo Diffie-Hellman não é exposto diretamente à cifra simétrica. Este segredo é submetido a uma função de derivação de chaves baseada em HMAC (**HKDF-SHA256**), parametrizada com uma string de contexto que inclui os nomes de utilizador dos dois participantes ordenados lexicograficamente (ex: `info=b'chat_sessao_alice_bob'`). Este vínculo ao par de participantes garante que dois pares distintos que obtivessem acidentalmente o mesmo segredo DH derivariam chaves de sessão distintas. O resultado é uma chave simétrica de 256 bits criptograficamente forte e uniformemente distribuída, utilizada para alimentar a cifra autenticada.

### 1.3. Fluxos de Comunicação Detalhados

#### A. Registo do Utilizador e Emissão de Certificados
No primeiro contacto de um utilizador com o ecossistema, o cliente gera localmente o seu par Ed25519. De seguida, envia um pedido de registo (`tipo: 'registar'`) contendo o seu nome de utilizador e a respetiva chave pública. O servidor, ao receber o payload, valida a disponibilidade do identificador e atua como uma **Autoridade de Certificação (CA) Raiz**. Utilizando o seu próprio par de chaves EC P-256 (`ca.key`), o servidor gera e assina digitalmente um certificado **X.509** para o utilizador, vinculando formalmente o seu nome à sua chave pública Ed25519. Este certificado é guardado na base de dados do servidor e enviado de volta ao cliente, que o armazena em ficheiro público (`<username>.crt`).

#### B. Autenticação e Login (Challenge-Response)
Nas sessões subsequentes, o utilizador efetua a autenticação através do comando `entrar`. Para obviar a necessidade de palavras-passe, o sistema recorre a um protocolo de desafio-resposta criptográfico:
1.  O cliente envia uma mensagem inicial de autenticação contendo apenas o seu identificador.
2.  O servidor gera um **nonce aleatório de 32 bytes** criptograficamente forte (`os.urandom(32)`) e envia-o como desafio (`tipo: 'desafio'`).
3.  O cliente recebe o desafio e assina digitalmente os bytes em bruto do nonce com a sua chave privada Ed25519, devolvendo a assinatura hexadecimal.
4.  O servidor extrai o certificado armazenado do utilizador, recupera a sua chave pública e efetua a verificação criptográfica da assinatura sobre o nonce enviado. Se a validação for bem-sucedida, a sessão de rede é associada ao utilizador e o acesso é concedido.

#### C. Acordo de Chaves E2E (Variante Station-to-Station)
Para iniciar uma conversação protegida, os clientes executam de forma autónoma uma variante simplificada e mútua do protocolo Station-to-Station (STS) intermediada pelo servidor:
1.  **Solicitação de Chave:** O iniciador (Alice) solicita ao servidor o certificado público do destinatário (Bob). O servidor responde com o certificado X.509 registado. Alice valida a assinatura do certificado utilizando a chave pública da CA do servidor (`ca.crt`) e confirma que o campo *Common Name* corresponde efetivamente a Bob.
2.  **Envio do Pedido Criptográfico ($g^x$):** Alice gera o seu par efémero X25519. De seguida, assina digitalmente a representação PEM da sua chave pública efémera com a sua chave privada de identidade Ed25519. O bloco contendo a chave efémera e a assinatura é encapsulado e enviado para Bob via servidor (`subtipo: 'inicio_ecdh'`).
3.  **Resposta e Validação ($g^y$):** Bob recebe a notificação, descarrega e valida o certificado de Alice junto da CA. Bob verifica a assinatura de Alice para assegurar a proveniência do pedido. Caso seja válida, Bob gera o seu próprio par efémero X25519 e assina digitalmente a concatenação exata da sua chave efémera com a chave efémera recebida de Alice ($g^y \parallel g^x$). Bob envia a sua chave efémera e a respetiva assinatura de volta a Alice (`subtipo: 'resposta_ecdh'`).
4.  **Derivação Final e Inicialização de Estado:** Alice recebe a resposta, verifica a assinatura de Bob e executa a operação Diffie-Hellman. Ambos os lados derivam de forma idêntica a chave AES de 256 bits via HKDF. Adicionalmente, inicializam localmente duas variáveis de controlo de fluxo: `tx_seq = 1` (contador de mensagens enviadas) e `rx_seq = 0` (registo da última mensagem recebida de forma legítima).

#### D. Canal de Mensagens Cifradas com Blindagem Sequencial
Com a sessão E2E ativa, o envio de texto é protegido contra adulteração e injeções históricas. Sempre que a Alice envia uma mensagem, o seu valor atual de `tx_seq` é convertido para binário e injetado diretamente como **Dados Autenticados Adicionais (AAD)** no algoritmo **AES-256-GCM**. O payload estruturado final enviado ao Bob via servidor contém o número da sequência em canal limpo e o bloco cifrado resultante. O Bob, ao receber o pacote, extrai a sequência e valida criptograficamente o criptograma usando esse mesmo valor como AAD, rejeitando imediatamente qualquer pacote cujo contador tenha sido adulterado ou cuja sequência cronológica seja inferior ou igual ao seu `rx_seq` local.

### 1.4. Funcionalidades e Valorizações Implementadas
O sistema cumpre os requisitos essenciais e materializa com sucesso três das melhorias avançadas listadas no enunciado:
* **Mensagens Offline:** Permite que o servidor retenha blobs cifrados opacos destinados a utilizadores desconectados, entregando-os imediatamente após a sua autenticação subsequente.
* **Infraestrutura de Chaves Públicas (PKI) Integrada:** O servidor atua como uma Autoridade de Certificação autoassinada que emite certificados X.509 aos clientes, vinculando as identidades às suas chaves públicas Ed25519.
* **Garantia de Forward Secrecy:** O acordo de chaves efémero baseado em X25519 garante que o comprometimento futuro da identidade a longo prazo de um utilizador não comprometa o histórico de sessões passadas.

---

## 2. Descrição Detalhada do Modelo de Segurança

### 2.1. Explicação Fundamentada das Primitivas Utilizadas
A seleção de algoritmos e primitivas criptográficas obedeceu aos critérios contemporâneos de eficiência computacional, resistência mecânica contra criptoanálise clássica e adequação ao ecossistema Python através da biblioteca nativa `cryptography`:
* **Ed25519:** Utilizado para chaves de identidade de longa duração, garantindo assinaturas rápidas e seguras com alta imunidade a ataques de canais laterais.
* **X25519:** Selecionado para a negociação efémera de chaves de sessão sobre curvas elípticas de alto desempenho (Curva 25519).
* **HKDF-SHA256:** KDF baseada em HMAC para purificar e expandir o segredo Diffie-Hellman numa chave simétrica estatisticamente uniforme.
* **AES-256-GCM:** Cifra simétrica autenticada (AEAD) que providencia confidencialidade, integridade e autenticidade numa única operação através da geração de uma tag GMAC de 16 bytes.

### 2.2. Análise das Garantias de Segurança Oferecidas e Mitigações Efetuadas
* **Confidencialidade Ponta-a-Ponta (E2E):** O conteúdo textual das mensagens trafega e reside no servidor exclusivamente sob a forma de criptogramas de alta entropia gerados por AES-256-GCM.
* **Blindagem Total Contra Ataques de Repetição (Replay Attacks):** Ao utilizar o contador de mensagens (`seq`) como *Associated Authenticated Data (AAD)* no AES-GCM, o recetor garante que o número da sequência não pode ser modificado em trânsito e rejeita pacotes antigos ou reinjetados tardiamente com base na variável `rx_seq`.
* **Resistência Ativa a Negação de Serviço (DoS) no Transporte:** A camada de *framing* TCP inspeciona o tamanho pretendido contra a constante sanitária `MAX_MSG_SIZE = 10MB`, mitigando falhas de alocação de memória (*Out-Of-Memory*).
* **Mitigação de Path Traversal no Sistema de Ficheiros:** O nome de utilizador é validado por expressão regular (`^[a-zA-Z0-9_-]{1,32}$`) antes de ser utilizado como componente de nome de ficheiro. Isto impede que um utilizador mal-intencionado forneça um input como `../../etc/passwd` para sobrescrever ficheiros arbitrários do sistema.
* **Encerramento Gracioso de Recursos:** A captura de exceções na `receiver_thread` garante que, quando o utilizador invoca o comando `sair`, a thread de escuta termine o seu ciclo de vida de forma limpa.

### 2.3. Identificação das Limitações Inerentes à Solução Desenvolvida
* **Dessincronização de Estado em Mensagens Offline (Protocolo Síncrono):** Se a Alice e o Bob estabelecerem uma sessão e o Bob fechar a aplicação (`sair`), o estado da sessão do Bob é inteiramente destruído na RAM para assegurar o *Forward Secrecy*. Se a Alice enviar uma mensagem offline para o Bob, esta será cifrada com a chave da sessão antiga. Quando o Bob voltar a entrar, o cliente do Bob rejeitará a mensagem com a nota `sessão E2E não estabelecida`.
* **Fragilidade do Modelo TOFU (Trust On First Use) na Distribuição da CA:** O cliente obtém o certificado público da Autoridade de Certificação através do envio de uma mensagem em canal aberto (`tipo: 'obter_ca'`) na sua primeira execução, caso o arquivo local `ca.crt` não esteja presente em disco.
* **Ausência de Cifra de Transporte no Canal Cliente-Servidor:** As mensagens de protocolo trocadas entre o cliente e o servidor (pedidos de routing, listas de utilizadores, mensagens de handshake ECDH) transitam em JSON sem encriptação de transporte (TLS). Um observador passivo na rede consegue identificar os metadados das conversas (quem fala com quem e quando), ainda que não consiga aceder ao conteúdo das mensagens, que permanece protegido ponta-a-ponta. Esta limitação está em linha com o modelo de ameaça definido no enunciado (servidor honesto mas curioso), mas seria mitigada com a adição de TLS no socket TCP.

---

## 3. Discussão de Melhorias Funcionais não Implementadas (Valorizações)

Conforme solicitado no enunciado, são aqui discutidas de forma clara e acessível as duas funcionalidades avançadas de valorização que não foram incluídas no código final do projeto, apresentando a respetiva lógica teórica de funcionamento:

### 3.1. Mensagens de Grupo (Chats Multi-utilizador)
A implementação atual está limitada a conversas entre dois utilizadores (1-para-1). Para suportar salas de chat com múltiplos participantes mantendo a cifra ponta-a-ponta, seria necessário alterar a forma como as chaves de cifragem são distribuídas.

#### Lógica de Funcionamento Semelhante ao Projeto:
Uma abordagem direta e compreensível seria baseada no conceito de uma **Chave de Grupo Simétrica**:
1.  **Criação do Grupo:** Quando um utilizador cria uma sala (ex: Alice, Bob e Carlos), o criador gera localmente uma chave simétrica aleatória para esse grupo específico.
2.  **Partilha Segura da Chave:** A Alice aproveita os canais de comunicação 1-para-1 que já sabe abrir com o Bob e com o Carlos (via acordo STS/X25519) e envia a chave do grupo cifrada diretamente a cada um deles. O servidor apenas reencaminha estes pacotes individuais, continuando sem acesso à chave.
3.  **Envio de Mensagens:** Quando qualquer membro do grupo envia uma mensagem para a sala, cifra o texto uma única vez usando a Chave do Grupo comum. O servidor recebe o criptograma e replica-o para todos os participantes. Todos conseguem decifrar a mensagem porque partilham a mesma chave.
4.  **Gestão de Membros:** Se um utilizador sair ou for removido do grupo, a chave antiga deixa de ser segura. O grupo teria de gerar e redistribuir uma nova Chave de Grupo entre os membros restantes, impedindo o utilizador removido de ler as conversas futuras.

### 3.2. Modo Descentralizado (Modelo Peer-to-Peer sem Servidor Central)
A arquitetura desenvolvida depende inteiramente de um servidor central para gerir os utilizadores online, guardar os certificados e encaminhar as mensagens. Se o servidor falhar, o sistema fica inoperacional.

#### Lógica de Funcionamento Semelhante ao Projeto:
Para criar um modo descentralizado, a aplicação cliente teria de passar a comunicar diretamente com outros clientes, num modelo **Peer-to-Peer (P2P)**:
1.  **Ligações Diretas:** Em vez de se ligarem ao IP do servidor, as instâncias da aplicação cliente estabeleceriam conexões de sockets TCP diretas entre si (usando o IP e a Porta da máquina do outro utilizador). Numa rede local (localhost), isto pode ser feito configurando os clientes para escutarem em portas diferentes.
2.  **Troca de Chaves Direta:** Sem o servidor a funcionar como Autoridade de Certificação (CA), os utilizadores teriam de trocar as suas chaves públicas Ed25519 de forma direta (por exemplo, importando manualmente o ficheiro `.crt` do amigo para a sua pasta da aplicação). A partir do momento em que conhecem a chave pública um do outro, o acordo de chaves efémero X25519 e a cifra AES-GCM funcionariam exatamente da mesma forma que no projeto atual, mas sem qualquer intermediário.
3.  **Limitação:** A grande desvantagem deste modelo simplificado seria a impossibilidade de enviar mensagens offline, uma vez que, sem um servidor centralizado com base de dados para reter os pacotes, as duas máquinas teriam de estar obrigatoriamente ligadas e ativas ao mesmo tempo para conseguir comunicar.
