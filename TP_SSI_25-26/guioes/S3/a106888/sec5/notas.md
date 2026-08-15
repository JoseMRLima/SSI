# Secção 5 — Notas

## Exercício 1

O `capsh --print` mostrou o bounding set com todas as capabilities disponíveis no sistema, e que o utilizador atual é `ubuntu` com `euid=1000`. O current set estava vazio (`=`), o que significa que o processo não tem nenhuma capability ativa.

## Exercício 2

Após compilar, o `getcap ./webserver` não devolveu nada — o executável não tem capabilities atribuídas.

## Exercício 3

Sem capabilities o resultado foi:
```
erro no bind: Permission denied
```

O kernel reserva as portas abaixo de 1024 para serviços de sistema. Por omissão só processos com `euid = 0` (root) ou com a capability `CAP_NET_BIND_SERVICE` podem fazer bind a essas portas.

Após `sudo setcap 'cap_net_bind_service=ep' ./webserver` o `getcap` confirmou:
```
./webserver cap_net_bind_service=ep
```

E o binding foi permitido sem correr como root:
```
sucesso: binding à porta 80 realizado.
```

O `ep` significa:
- `e` — Effective: ativa imediatamente para o processo
- `p` — Permitted: define o máximo que o processo pode ter