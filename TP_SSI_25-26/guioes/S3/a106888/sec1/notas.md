# Secção 1 — Notas

## Exercício 2

As permissões por omissão de um ficheiro novo dependem da `umask` do utilizador.
Com `umask 002` (valor do ambiente usado), um ficheiro criado com `echo` fica com `rw-rw-r--` (664):
- Dono: leitura e escrita
- Grupo: leitura e escrita
- Outros: só leitura

## Exercício 3

`chmod 666` dá leitura e escrita a todos (dono, grupo e outros).

## Exercício 4

`chmod 500` dá ao dono leitura e execução sem escrita, e remove tudo ao grupo e outros.

## Exercício 5

`chmod 400` deixa só o dono ler. Grupo e outros não têm acesso nenhum.

## Exercício 6

Diretorias criadas com `mkdir` ficam com `rwxrwxr-x` (775):
- `r` — permite listar o conteúdo com `ls`
- `w` — permite criar ou apagar ficheiros dentro
- `x` — permite entrar com `cd` e aceder aos ficheiros

## Exercício 7

O resultado foi `drwxrw-r--` — o grupo perdeu a execução e passou de `rwx` para `rw-`, e os outros de `r-x` para `r--`.