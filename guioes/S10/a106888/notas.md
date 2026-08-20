# Semana 10 — Notas

## Q1 — (Task 4) Para que serve a verificação do GUID?

O script tem uma condição que verifica se o GUID do utilizador atual é diferente do GUID do Samy. Isto serve para que quando o próprio Samy visita o seu perfil, o pedido AJAX não seja enviado — caso contrário o Samy estaria a tentar adicionar-se a si mesmo como amigo, o que não faz sentido e podia causar erros ou chamar atenção. Basicamente é uma proteção para o script não disparar na conta do atacante.

## Q2 — (Task 4) Por que se usa GET e não POST?

Ao analisar o pedido HTTP que o Elgg faz quando carregamos no botão "Add Friend" normalmente (usando as Developer Tools do browser), vê-se que é um GET com os parâmetros todos na URL (`friend`, `__elgg_ts`, `__elgg_token`). O script AJAX replica exatamente isso. Não foi uma escolha nossa, é simplesmente como o endpoint do Elgg funciona.

## Q3 — Que tipo de XSS é este ataque?

É **Stored XSS** (ou Persistent XSS). O payload fica guardado na base de dados do servidor, no campo "About me" do perfil do Samy. Cada vez que alguém visita o perfil, o servidor devolve a página com o script e o browser executa-o automaticamente.

Isto é diferente do Reflected XSS, onde o payload viajava numa URL e o servidor apenas o "refletia" na resposta — nesse caso a vítima teria de clicar num link malicioso. Aqui não, basta visitar o perfil para o ataque acontecer, o que torna o Stored XSS muito mais perigoso e é exatamente o que tornou o Samy Worm tão eficaz em 2005.
