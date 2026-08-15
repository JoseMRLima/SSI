# Secção 2 — Notas

## Exercício 2 — Vulnerabilidade

O programa abre `/etc/passwd` em modo de escrita com `open()` antes de largar privilégios, obtendo o fd 3. Depois faz `setuid(getuid())` para voltar ao utilizador normal e lança uma shell. O fd aberto para `/etc/passwd` não é fechado, por isso a shell herda-o e consegue escrever no ficheiro mesmo sem permissões — outro caso de capability leaking.

## Exercício 3 — Exploit

Dentro da shell lançada pelo `passwdleak`, o fd 3 está aberto para escrita em `/etc/passwd`. Para explorar isso basta correr:

```bash
echo 'ssihacker::0:0::/root:/bin/sh' >&3
```

Isto adiciona uma nova entrada ao `/etc/passwd` com UID 0 (root) e sem password.

## Exercício 4 — Implicações

Após adicionar a entrada, foi possível fazer login como `ssihacker` sem password:

```bash
su - ssihacker
#
```

O `#` indica que se entrou como root. Como o UID é 0, o utilizador tem privilégios de root completos podendo fazer qualquer coisa no sistema.

## Exercício 5 — Correção

A correção é fechar o fd com `close(fd)` antes de chamar `setuid`. Com a correção aplicada, ao tentar escrever em `/etc/passwd` dentro da shell do `fix` o resultado foi:

```
sh: 1: 3: Bad file descriptor
```

O fd 3 já não existe na shell e não é possível escrever em `/etc/passwd`.