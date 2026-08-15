# Semana 6 — Notas

## Q1 — Impacto de usar um NONCE fixo no ChaCha20
O ChaCha20 é uma cifra de stream síncrona, o que significa que um par (chave, nonce) vai gerar sempre exatamente o mesmo keystream. Se fixarmos o nonce (por exemplo, usando tudo zeros), a mesma chave vai produzir a mesma sequência de bits em todas as cifrações. Isto destrói a confidencialidade: se um atacante intercetar dois criptogramas (`c1` e `c2`), basta fazer `c1 XOR c2` para obter o XOR das mensagens originais (`m1 XOR m2`). É a mesma vulnerabilidade de reutilizar a chave num One-Time Pad. O propósito do nonce é precisamente garantir que o keystream nunca se repita, mesmo que a chave se mantenha a longo prazo.

## Q2 — Difusão no ChaCha20 (alteração de 1 bit)
Por ser uma cifra de stream, o ChaCha20 opera bit a bit (ou byte a byte), fazendo um simples XOR entre o texto limpo e o keystream. Se alterarmos apenas 1 bit no texto limpo e cifrarmos com a mesma chave e nonce, exatamente **1 bit** será alterado no criptograma (na mesma posição). Não existe qualquer mecanismo de difusão nesta cifra; uma mudança no input não se propaga de todo para o resto do output.

## Q3 — Alteração de 1 bit no criptograma: CBC vs CTR
**Modo CTR:** Comporta-se de forma idêntica a uma cifra de stream pura. O AES é usado apenas para gerar o keystream, que sofre XOR com o texto limpo. Por isso, alterar 1 bit no criptograma afeta apenas **1 bit** no texto decifrado, exatamente na mesma posição. A corrupção não se espalha.

**Modo CBC:** Neste modo, a decifração de cada bloco depende do bloco de criptograma anterior (`P_i = D(C_i) XOR C_{i-1}`). Se alterarmos 1 bit no bloco `C_k` do criptograma:
- O bloco `P_k` correspondente fica totalmente destruído após decifrar (são afetados **128 bits**, dado que a decifração AES altera drasticamente o bloco).
- No bloco seguinte (`P_{k+1}`), a alteração reflete-se em exatamente **1 bit** na mesma posição, porque o bloco `C_k` (agora com um bit alterado) entra diretamente na operação XOR da decifração seguinte.

## Q4 — Impacto do chacha20_int_attck no AES-CBC e AES-CTR
**No AES-CTR:** O ataque de integridade funciona na perfeição, tal como no ChaCha20. Como a relação matemática é `ctxt = ptxt XOR keystream`, podemos manipular bytes específicos do criptograma para forçar um resultado previsível no texto decifrado, sem estragar o resto da mensagem.

**No AES-CBC:** O ataque é destrutivo e ruidoso. É verdade que conseguimos usar a propriedade do XOR para alterar de forma controlada um byte específico no bloco seguinte (`P_{k+1}`), mas ao fazer isso corrompemos a 100% o bloco atual (`P_k`). Ou seja, perdemos 16 bytes de informação legítima só para conseguir manipular um byte da frente. O ataque funciona em teoria, mas deixa um rasto óbvio de corrupção.

## Q5 — Função do salt e do NONCE no Password-Based Encryption
Ambos são vitais, mas operam em fases completamente diferentes do processo:
- **Salt:** É usado na derivação da chave (PBKDF2). Serve para garantir que, mesmo que se use a mesma palavra-passe em ficheiros diferentes, a chave criptográfica resultante seja diferente. Isto neutraliza ataques baseados em dicionários e *rainbow tables*.
- **NONCE:** É usado na fase de cifração (ChaCha20). Garante que, mesmo que se chegue à mesma chave (por exemplo, se reaproveitarmos o salt e a password), o keystream gerado seja distinto em cada operação.

Juntos, formam uma defesa em profundidade: garantem que cifrar a mesma mensagem várias vezes com a mesma palavra-passe gera sempre criptogramas únicos e sem relação entre si.