# Semana 5 — Notas

## César
A cifra de César baseia-se num deslocamento simples (shift) de cada letra do alfabeto por um valor fixo. Por exemplo, usando a chave `G` (que corresponde a um shift de 6), o `A` passa a `G`, o `B` passa a `H`, e por aí fora. Para decifrar, basta subtrair esse mesmo deslocamento.

Como o alfabeto só tem 26 letras, o espaço de chaves é minúsculo. Isto faz com que um ataque de força bruta seja trivial: basta iterar pelos 26 deslocamentos possíveis e verificar qual deles gera um texto que contenha pelo menos uma das palavras que estamos à procura.

## Vigenère
No fundo, a cifra de Vigenère é a aplicação de várias cifras de César em sequência, repetindo a chave ciclicamente. Se a chave for `BACO` (shifts 1, 0, 2, 14), a primeira letra sofre um shift de 1, a segunda de 0, a terceira de 2, etc. Quando a chave acaba, volta ao início.

Para quebrar a cifra (assumindo que já sabemos que o tamanho da chave é `k`), a estratégia passa por dividir o criptograma em `k` fatias. Como cada fatia foi cifrada com a mesma letra (ou seja, com o mesmo shift estático), o problema reduz-se a resolver `k` cifras de César. A partir daí, fazemos uma análise de frequência clássica: calculamos o shift que melhor aproxima as frequências de cada fatia às frequências típicas das letras em português, sabendo que o A, E, O e S são as mais comuns. Depois de deduzir as letras mais prováveis para cada posição da chave, testamos as combinações até o texto resultante bater certo com as palavras-alvo.

## Q1 — Diferenças entre otp.py e bad_otp.py
Sim, o comportamento é visivelmente diferente na prática. O grande problema do `bad_otp.py` é que inicializa o gerador de números pseudo-aleatórios com uma seed de apenas 2 bytes (`random.seed(random.randbytes(2))`).

Isto quer dizer que, independentemente de pedirmos uma chave de 10 bytes ou de 1000 bytes, a entropia real está limitada a esses 2 bytes iniciais. O espaço de seeds tem apenas 65.536 valores possíveis. Se gerarmos chaves consecutivamente, vamos rapidamente começar a observar repetições. Pelo contrário, o `otp.py` usa o `os.urandom`, que vai buscar entropia segura ao sistema operativo (CSPRNG), produzindo chaves efetivamente imprevisíveis e sem padrões detetáveis.

## Q2 — O ataque ao bad_otp contradiz a segurança absoluta do OTP?
Não há qualquer contradição. A prova de segurança perfeita do One-Time Pad (o Teorema de Shannon) exige três condições para ser matematicamente inquebrável: a chave tem de ser maior ou igual à mensagem, nunca pode ser reutilizada, e tem de ser **totalmente aleatória**.

O `bad_otp.py` quebra exatamente esta última regra. Como a entropia da chave é baixíssima, um atacante só precisa de varrer as 65.536 seeds possíveis para recriar a chave e decifrar o texto. Ou seja, o ataque não explora nenhuma falha no conceito do OTP ou na operação XOR; explora apenas a péssima implementação do gerador que produziu a chave. A teoria do OTP continua intacta.

## Q3 — Cifrar duas mensagens com a mesma chave OTP
Se cifrarmos duas mensagens (`m1` e `m2`) com a mesma chave OTP (`k`), obtemos:
`c1 = m1 XOR k`  
`c2 = m2 XOR k`

O erro fatal de reutilizar a chave é que o atacante pode simplesmente fazer o XOR entre os dois criptogramas. Como `k XOR k = 0`, a chave cancela-se mutuamente e obtemos:
`c1 XOR c2 = m1 XOR m2`

Ficamos assim com o XOR dos dois textos em limpo. A partir daqui, usa-se uma técnica conhecida como *crib-dragging*. O atacante adivinha uma palavra provável de estar no texto (um *crib*) e vai fazendo XOR dessa palavra ao longo de `m1 XOR m2`. Quando a palavra "encaixa" na posição certa de uma das mensagens, o resultado devolve um bocado de texto legível da outra mensagem. Com alguma tentativa e erro linguístico, a recuperação dos textos originais acaba por ser relativamente simples.