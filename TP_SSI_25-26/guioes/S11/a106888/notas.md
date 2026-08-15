# Semana 11 — Notas

## Q1 — Por que o stack canary impede o exploit mesmo sem NX ou ASLR?

O canário é um valor que o compilador mete na stack entre o buffer e o endereço de retorno. Antes de fazer o `RET`, o programa verifica se esse valor ainda está intacto. Num overflow linear como este, para conseguirmos sobrescrever o endereço de retorno temos obrigatoriamente de passar por cima do canário primeiro — ou seja, ele é sempre corrompido. O programa deteta isso e aborta antes de saltar para lado nenhum.

## Q2 — Por que o PIE/ASLR por si só impede o exploit?

Sem `-no-pie` o endereço da `secret_function` muda a cada execução. Vimos isso quando compilámos sem a flag — o endereço passou de `0x4011b6` para `0x557a8d29b1c9`. O payload que tínhamos construído usa o endereço fixo, por isso quando é executado o RIP aponta para uma zona inválida e dá segfault. Para contornar isto precisávamos de saber o endereço atual em runtime, o que normalmente exige outro tipo de vulnerabilidade (como uma format string) para o vazar.

## Q3 — Relação entre as três mitigações

As três atuam em alturas diferentes e protegem coisas diferentes. O canário deteta o overflow antes do `RET`. O ASLR torna os endereços imprevisíveis. O NX impede correr código injetado na stack. Nenhuma delas é suficiente sozinha — por exemplo ROP bypassa o NX — mas juntas tornam o ataque muito mais difícil.

## Q4 — Por que usar `sys.stdout.buffer.write` em vez de `print`?

O endereço da `secret_function` em little-endian tem bytes nulos (`\x00`). O `print` do Python e a bash tratam `\x00` como fim de string e cortam o input aí. Escrevendo diretamente para `stdout.buffer` os bytes nulos chegam intactos ao processo.

---

## Q5 — O que indica o aviso do compilador? (Exercício 6)

O aviso diz que estamos a passar uma variável diretamente como string de formato ao `printf` sem argumentos adicionais. É útil porque o compilador consegue detetar este padrão em análise estática. Não é suficiente porque há casos em que não consegue detetar — por exemplo se a chamada for feita através de um ponteiro de função ou se o código estiver noutra unidade de compilação.

## Q6 — Por que o printf não deteta que não foram passados argumentos? (Exercício 7)

O `printf` não tem forma de saber quantos argumentos foram passados. Ele lê a string de formato caráter a caráter e cada vez que encontra um `%p` vai buscar o próximo valor à stack como se fosse um argumento — não há nenhuma verificação. É uma limitação do C: o número de argumentos variádicos não é passado implicitamente.

## Q7 — O que demonstra o Exercício 8? (Exercício 8)

Conseguimos ler o valor `0xcafebabe` diretamente da stack sem ter acesso ao código ou ao processo — só com uma entrada maliciosa. Num caso real isto podia ser usado para vazar endereços de retorno ou outros dados sensíveis que estejam na memória, e com isso contornar o ASLR antes de lançar um segundo ataque.
