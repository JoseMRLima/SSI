#!/bin/bash
# Secção 1 — Capability Leaking

# setup
gcc -o backupssi backupssi.c
sudo chown root:root backupssi
sudo chmod 4755 backupssi

# Exercício 1 - executar o backupssi e dentro da shell confirmar o fd
# ./backupssi
# ls /proc/self/fd

# Exercício 3 - compilar o exploit, correr o backupssi e dentro da shell correr o exploit
gcc -o exploit exploit.c
# ./backupssi
# ./exploit

# Exercício 4 - compilar a correção, correr e dentro da shell correr o exploit
gcc -o fix fix.c
sudo chown root:root fix
sudo chmod 4755 fix
# ./fix
# ./exploit