#!/bin/bash
# Secção 2 — Gestão de Utilizadores e de Grupos
# executar com sudo

# Exercício 0 - observar /etc/passwd e /etc/group
cat /etc/passwd
cat /etc/group

# Exercício 1 - criar um utilizador por membro da equipa
sudo adduser --disabled-password --gecos "" aluno1
sudo adduser --disabled-password --gecos "" aluno2
sudo adduser --disabled-password --gecos "" aluno3

# Exercício 2 - criar grupos e adicionar membros
sudo groupadd grupo-ssi
sudo groupadd par-ssi

sudo usermod -aG grupo-ssi aluno1
sudo usermod -aG grupo-ssi aluno2
sudo usermod -aG grupo-ssi aluno3

sudo usermod -aG par-ssi aluno1
sudo usermod -aG par-ssi aluno2

# Exercício 3 - observar novamente /etc/passwd e /etc/group
cat /etc/passwd
cat /etc/group

# Exercício 4 - alterar o dono de braga.txt para aluno1
sudo chown aluno1 ../sec1/braga.txt
ls -l ../sec1/braga.txt

# Exercício 5 - ler braga.txt como utilizador atual
cat ../sec1/braga.txt

# Exercício 6 - iniciar sessão com aluno1
su - aluno1

# Exercício 7 - executar id e groups
id
groups

# Exercício 8 - ler braga.txt como aluno1
cat ../sec1/braga.txt

# Exercício 9 - tentar entrar em dir2
cd ../sec1/dir2