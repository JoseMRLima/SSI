#!/bin/bash
# Secção 3 — Utilizador Real vs. Efetivo e Elevação de Privilégio
# executar com sudo

# Exercício 1 - compilar o reader.c
gcc -o reader reader.c

# Exercício 2 - criar o utilizador userssi
sudo adduser --disabled-password --gecos "" userssi

# Exercício 3 - alterar o dono do executável e de braga.txt para userssi
sudo chown userssi reader
sudo chown userssi ../sec1/braga.txt
ls -l reader ../sec1/braga.txt

# Exercício 4 - executar o reader com braga.txt como utilizador atual
./reader ../sec1/braga.txt

# Exercício 5 - definir setuid no executável
sudo chmod u+s reader
ls -l reader

# Exercício 6 - executar novamente após setuid
./reader ../sec1/braga.txt