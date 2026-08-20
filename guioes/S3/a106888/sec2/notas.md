# Secção 2 — Notas

## Exercício 3

No `/etc/passwd` apareceram três novas linhas no fim, uma por cada utilizador criado:
```
aluno1:x:1001:1001:,,,:/home/aluno1:/bin/bash
aluno2:x:1002:1002:,,,:/home/aluno2:/bin/bash
aluno3:x:1003:1003:,,,:/home/aluno3:/bin/bash
```
O `x` no segundo campo significa que a password está guardada em `/etc/shadow`. Os UIDs começam em 1001 porque o 1000 já está ocupado pelo utilizador `ubuntu`.

No `/etc/group` apareceram também novas linhas, incluindo os dois grupos criados no fim:
```
grupo-ssi:x:1004:aluno1,aluno2,aluno3
par-ssi:x:1005:aluno1,aluno2
```
É possível ver que os membros de cada grupo estão listados separados por vírgula.

## Exercício 7

Saída obtida:
```
uid=1001(aluno1) gid=1001(aluno1) groups=1001(aluno1),100(users),1004(grupo-ssi),1005(par-ssi)
aluno1 users grupo-ssi par-ssi
```
O `uid` é o identificador do utilizador, o `gid` é o grupo principal e `groups` lista todos os grupos a que pertence, incluindo os secundários.

## Exercício 8

O acesso foi negado com `Permission denied`. Apesar de `aluno1` ser o dono de `braga.txt`, o ficheiro está dentro de `/home/ubuntu` que não tem permissão de execução para outros utilizadores, por isso `aluno1` não consegue sequer aceder à diretoria onde o ficheiro está.

## Exercício 9

O acesso foi negado com `Permission denied`. `dir2` tem permissões `drwxrw-r--` (764) e o dono é `ubuntu`. Como `aluno1` não é o dono, o sistema aplica as permissões de grupo ou outros, que não têm execução, impedindo o `cd`.