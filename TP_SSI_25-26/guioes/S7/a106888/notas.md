# Semana 7 — Notas

## Q1 — Padding e Ataque de Extensão (Length Extension Attack)

O SHA256 processa os dados em blocos fixos de 64 bytes (512 bits). Antes de processar a mensagem, é sempre adicionado um padding obrigatório: um byte `\x80`, seguido de bytes a zero, e terminando com 8 bytes que indicam o tamanho original em bits.

No nosso ataque ao prefix-MAC ($H(k \parallel m)$), o input original tem **94 bytes** (32 bytes da chave + 62 bytes do URL). Como 94 bytes não cabem num único bloco, o SHA256 usa um bloco inteiro (64 bytes) e sobram 30 bytes para o segundo bloco. Para preencher este segundo bloco até aos 64 bytes, são precisos **34 bytes** de padding.

Estes 34 bytes contêm:
* 1 byte `\x80`
* 25 bytes `\x00`
* 8 bytes com o valor `0x00000000000002f0` (que é 94 bytes × 8 = 752 bits).

A vulnerabilidade explorada (usando o `hashpumpy`) é que, sabendo o tamanho da chave e o MAC original, conseguimos "retomar" o estado interno do hash a partir do final deste padding e adicionar a nossa extensão (`&admin=true`), forjando um MAC válido sem nunca saber a chave secreta.

## Q2 — Diferença entre AES-CTR+HMAC e AES-GCM

A diferença prática principal está no tamanho final do ficheiro (overhead) e na forma como a autenticação é integrada. Importa referir que nenhum dos modos utiliza padding na mensagem original, pois ambos funcionam como cifras de stream.

| Componente | pbenc_aes_ctr_hmac.py | pbenc_aes_gcm.py |
| :--- | :--- | :--- |
| **Salt (PBKDF2)** | 16 bytes | 16 bytes |
| **Nonce/IV** | 16 bytes | 12 bytes |
| **Tag de Autenticação** | 32 bytes (HMAC-SHA256) | 16 bytes (GCM) |
| **Overhead Total**| **64 bytes** | **44 bytes** |

O ficheiro gerado pelo AES-GCM é sempre **20 bytes mais pequeno**.

Para além da redução de tamanho, a grande vantagem do GCM é ser um modo de Cifra Autenticada (AEAD) nativo. Enquanto no primeiro script tivemos de implementar o modo *Encrypt-then-MAC* manualmente (derivando chaves diferentes e chamando o HMAC à parte), o GCM garante a confidencialidade e a integridade de forma simultânea e interna. Isto reduz substancialmente o risco de introduzir vulnerabilidades por erros de implementação.