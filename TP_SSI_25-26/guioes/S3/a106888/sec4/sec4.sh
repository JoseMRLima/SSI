#!/bin/bash
# Secção 4 — Listas Estendidas de Controlo de Acesso (ACLs)
# executar com sudo
# requer o pacote acl: sudo apt install acl

# Exercício 1 - ver ACL inicial de porto.txt
getfacl ../sec1/porto.txt

# Exercício 2 - dar permissão de escrita ao grupo-ssi via ACL
sudo setfacl -m "g:grupo-ssi:w" ../sec1/porto.txt

# Exercício 3 - ver ACL atualizada e permissões
getfacl ../sec1/porto.txt
ls -l ../sec1/porto.txt

# Exercício 4 - testar escrita e leitura como aluno1
sudo -u aluno1 bash -c "echo 'linha adicionada por aluno1' >> ../sec1/porto.txt"
sudo -u aluno1 cat ../sec1/porto.txt