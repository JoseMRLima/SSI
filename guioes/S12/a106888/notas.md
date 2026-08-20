# Semana 12 — Notas

## Exercício 5: Reflexão

### Q1 — Causa comum a buffer overflows, format strings, SQL injection e command injection

Em todos estes casos o problema é o mesmo: dados controlados pelo utilizador são misturados com código ou comandos sem separação clara entre os dois. No buffer overflow, a entrada sobrescreve memória que devia ser código de controlo. Nas format strings, a entrada é interpretada como instruções de formatação. No SQL injection, a entrada torna-se parte da query. No command injection, a entrada é executada como comando de shell. A raiz é sempre a mesma — o programa não distingue entre "isto é dado" e "isto é instrução".

### Q2 — Por que a validação de entradas não é suficiente sozinha

A validação tenta bloquear entradas maliciosas antes de chegarem ao ponto vulnerável, mas é fácil de contornar. Listas negras são incompletas — há sempre codificações, variações ou casos edge que não foram previstos. Além disso, a validação tende a acontecer num sítio e o uso da variável noutro, e a lógica pode divergir com o tempo. A abordagem mais robusta é garantir que mesmo que chegue uma entrada maliciosa, ela não possa ser interpretada como código — o que é o que as queries parametrizadas e o `subprocess` sem shell fazem.

### Q3 — Parametrização e privilégio mínimo

A parametrização resolve o problema na origem: em vez de tentar filtrar o que é perigoso, garante estruturalmente que os dados nunca se tornam código. Na Semana 11 o equivalente seria usar funções com verificação de limites (`strncpy`, `snprintf`) em vez de tentar validar o tamanho antes. O privilégio mínimo também se aplica: na Semana 12, se a aplicação só precisasse de ler a base de dados não devia ter permissões de escrita; se não precisasse de shell não devia invocar `os.system()`. Na Semana 11, compilar sem `-z execstack` é um exemplo de privilégio mínimo — a stack não precisa de ser executável, por isso não deve ser.

### Q4 — Diferenças entre buffer overflow e format string quanto ao acesso à memória

Os dois ataques usam a stack mas de forma diferente. No buffer overflow (Parte A), a escrita é linear e o atacante sobrescreve memória de forma cega — enche o buffer, passa por cima do canário e escreve sobre o endereço de retorno. Não lê nada, só escreve. Na format string (Parte B), o mecanismo é oposto: o atacante usa `%p` ou `%x` para ler valores da stack um a um, de forma controlada e sem corromper nada. Consegue navegar a stack posição a posição e extrair dados específicos como endereços ou valores de variáveis locais. Num ataque avançado com `%n` também pode escrever em endereços arbitrários, o que não é possível com um overflow simples sem conhecer primeiro os endereços — o que a format string permite descobrir.
