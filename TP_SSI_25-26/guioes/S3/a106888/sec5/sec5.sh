#!/bin/bash
# Secção 5 — Capabilities do Linux
# executar com sudo
# requer: sudo apt install libcap2-bin

# Exercício 1 - listar capabilities disponíveis no sistema
capsh --print

# Exercício 2 - compilar o webserver.c e ver capabilities antes de setcap
gcc -o webserver webserver.c
getcap ./webserver

# Exercício 3 - tentar binding à porta 80 sem capabilities
./webserver 80

# atribuir CAP_NET_BIND_SERVICE e repetir
sudo setcap 'cap_net_bind_service=ep' ./webserver
getcap ./webserver
./webserver 80