# Semana 8 — Notas

## Q1 — Perfect Forward Secrecy (PFS) na aplicação

**Não garante PFS total para múltiplas mensagens dentro da mesma sessão.** Nesta implementação, o segredo partilhado $K$ é calculado apenas uma vez através da troca de chaves DH efémeras ($x$ e $y$). Se este segredo $K$ for comprometido a meio da comunicação, um atacante consegue derivar a mesma chave AES (através da HKDF) e decifrar **todas** as mensagens trocadas durante essa sessão. 

Para que a aplicação garantisse PFS de forma granular (mensagem a mensagem), seria necessário implementar um mecanismo de *ratcheting* (como o utilizado no protocolo Signal), em que o material criptográfico é continuamente renovado a cada iteração, garantindo que o compromisso de uma chave atual não afeta as mensagens passadas. 
*(Nota: O uso de chaves DH efémeras garante, no entanto, PFS entre sessões independentes, visto que os parâmetros $x$ e $y$ são descartados no fim).*

## Q2 — Armazenamento das chaves públicas

A informação das chaves públicas dos participantes encontra-se armazenada e distribuída através dos seus **Certificados X.509** (`Alice.crt` e `Bob.crt`). 
Cada certificado contém a chave pública do respetivo utilizador, os seus dados de identidade, e uma assinatura digital da Autoridade de Certificação (CA) que vincula essa identidade à chave. A chave pública da própria CA — necessária para validar as restantes assinaturas — está armazenada no seu certificado auto-assinado raiz (`CA.crt`).

## Q3 — Ataque MitM sem verificação do Certificado

**Deixa de ser imune**, ficando totalmente vulnerável a ataques *Man-in-the-Middle* (MitM). 
A verificação da assinatura (passo previsto no Station-to-Station) apenas prova que quem enviou a mensagem possui a chave privada correspondente à chave pública apresentada. 

Se a Alice omitir a verificação do certificado contra a Autoridade de Certificação (CA), um atacante (Mallory) pode intercetar a ligação, gerar o seu próprio par de chaves, criar um certificado falso com o nome "Bob", e assinar a troca de chaves DH com a sua chave privada. Como a Alice não confirma na CA se aquele certificado é legítimo, a matemática da assinatura vai dar como válida, e a Alice irá estabelecer um túnel seguro (e partilhar o segredo) diretamente com o atacante, pensando que está a falar com o Bob.