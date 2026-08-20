# Secção 3 — Notas

## Exercício 4

`braga.txt` tem permissões `r--------` (400) e o dono é `userssi`. O utilizador atual (`ubuntu`) não é `userssi`, por isso o processo corre com um `euid` sem permissão de leitura e o resultado foi:
```
erro ao abrir o ficheiro: Permission denied
```

## Exercício 5

Após `chmod u+s reader` as permissões passaram a `-rwsrwxr-x`. O `s` no lugar do `x` do dono indica que o bit setuid está ativo.

## Exercício 6

Com o setuid ativo, quando o executável corre o kernel define o `euid` do processo como o UID do dono do ficheiro (`userssi`). Como `userssi` é o dono de `braga.txt` e tem permissão de leitura, o acesso foi permitido e o resultado foi:
```
Braga é o quarto distrito com mais população de Portugal.
```