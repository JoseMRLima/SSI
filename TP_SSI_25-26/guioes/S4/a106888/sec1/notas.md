# Secção 1 — Notas

## Exercício 2 — Vulnerabilidade

O programa abre `/root` com `open()` antes de largar privilégios, obtendo o fd 3. Depois faz `setuid(getuid())` para voltar ao utilizador normal e lança uma shell com `execve`. O problema é que o fd aberto para `/root` não é fechado antes do `setuid`, por isso a shell herda-o e consegue aceder a `/root` mesmo sem ter permissões — é o que se chama capability leaking.

## Exercício 3 — Exploit

Dentro da shell lançada pelo `backupssi`, o fd 3 está aberto e aponta para `/root`. O exploit usa `fdopendir` para listar o conteúdo do diretório via fd herdado. O output obtido foi:

```
fd 3 aponta para: /root
conteudo de /root:
  .profile
  backupssi
  .
  ..
  .bashrc
  .ssh
```

Isto demonstra que o utilizador `ubuntu` conseguiu listar o conteúdo de `/root` sem ter permissões para isso.

## Exercício 4 — Correção

A correção é fechar o fd com `close(dfd)` antes de chamar `setuid`. Com a correção aplicada, ao correr o exploit dentro da shell do `fix` o resultado foi:

```
readlink: No such file or directory
```

O fd 3 já não existe na shell e o acesso a `/root` é negado.