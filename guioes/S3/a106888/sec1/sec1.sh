#!/bin/bash
# Secção 1 — Utilizador, Grupo e Permissão

# Exercício 1 - criar ficheiros com texto
echo "Lisboa é a capital de Portugal." > lisboa.txt
echo "Porto é o segundo maior distrito de Portugal." > porto.txt
echo "Braga é o quarto distrito com mais população de Portugal." > braga.txt

# Exercício 2 - ver permissões de lisboa.txt
ls -l lisboa.txt

# Exercício 3 - dono, grupo e outros com leitura e escrita
chmod 666 lisboa.txt
ls -l lisboa.txt

# Exercício 4 - dono só com leitura e execução
chmod 500 porto.txt
ls -l porto.txt

# Exercício 5 - só o dono pode ler
chmod 400 braga.txt
ls -l braga.txt

# Exercício 6 - criar diretorias e ver permissões
mkdir dir1 dir2
ls -ld dir1 dir2

# Exercício 7 - tirar execução de dir2 para grupo e outros
chmod 764 dir2
ls -ld dir2