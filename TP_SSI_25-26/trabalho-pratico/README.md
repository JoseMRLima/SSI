# Chat E2EE — SSI 2025/26

Sistema de chat com End-to-End Encryption (E2EE) em Python, desenvolvido para o projeto de Segurança de Sistemas Informáticos. Para detalhes de arquitetura e modelo de segurança consulta o [relatório](Relatorio-TP-Final.md).

## Dependências

```bash
pip install cryptography
```

## Como executar

### 1. Iniciar o servidor

```bash
python3 server.py
```

### 2. Registar (primeira vez)

```bash
python3 client.py registar alice
python3 client.py registar bob
```

Será pedida uma password para proteger a chave privada gerada localmente.

### 3. Autenticar (sessões seguintes)

```bash
python3 client.py entrar alice
```

## Comandos do cliente

| Comando | Descrição |
|---|---|
| `listar` | Lista utilizadores online |
| `chat <user>` | Inicia troca de chaves E2E com `user` |
| `aceitar <user>` | Aceita o pedido de sessão de `user` |
| `msg <user> <texto>` | Envia mensagem cifrada para `user` |
| `sair` | Termina a sessão |

## Exemplo de sessão

**Terminal Alice:**
```
[alice]> chat bob
Pedido enviado. Aguarda que bob aceite ('aceitar alice').
A aguardar resposta ECDH (timeout: 120s)...

Sessão E2E estabelecida com bob. Usa: msg bob <texto>

[alice]> msg bob Olá Bob!
```

**Terminal Bob:**
```
[Chat] alice quer conversar contigo. Aceita com: aceitar alice

[bob]> aceitar alice
Sessão E2E estabelecida com alice. Usa: msg alice <texto>

[alice] Olá Bob!
```
