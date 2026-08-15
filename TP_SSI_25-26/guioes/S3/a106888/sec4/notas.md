# Secção 4 — Notas

## Exercício 3

Antes do `setfacl` o `getfacl` mostrava:
```
# file: ../sec1/porto.txt
# owner: root
# group: root
user::r-x
group::---
other::---
```

Depois:
```
# file: ../sec1/porto.txt
# owner: root
# group: root
user::r-x
group::---
group:grupo-ssi:-w-
mask::-w-
other::---
```

O `ls -l` passa a mostrar `-r-x-w----+`, com o `+` no fim a indicar que há ACL ativa. A máscara foi atualizada automaticamente para `-w-`, refletindo as permissões máximas das entradas de grupo.

## Exercício 4

A escrita foi bem-sucedida porque `grupo-ssi` tem permissão `w` via ACL. A leitura falhou com `Permission denied` porque a ACL só concedeu `w` e não `r`. Isto mostra que as ACLs permitem uma granularidade impossível com as permissões UNIX tradicionais.