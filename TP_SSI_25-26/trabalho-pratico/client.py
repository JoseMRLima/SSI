import socket
import threading
import sys
import queue
import re
from getpass import getpass
from pathlib import Path
import crypto_utils as cu

SERVER_HOST = 'localhost'
SERVER_PORT = 8443

# Estado global do cliente
sock = None
username = None
private_key = None       # Ed25519 — chave de longa duração (identidade)
public_key = None
ca_cert = None           # Certificado da CA do servidor

# Guarda o estado completo da sessão: chave AES, sequência de envio e última sequência recebida
active_sessions = {}     # username -> {'key': bytes, 'tx_seq': int, 'rx_seq': int}
pending_ecdh = {}        # username -> (X25519PrivateKey, pub_pem_bytes) aguardando resposta
pending_requests = {}    # username -> conteudo do 'inicio_ecdh' recebido (aguarda 'aceitar')

# Filas de mensagens entre a thread de fundo e a thread principal
response_queue = queue.Queue()   # respostas do servidor (ok, erro, lista, chave, desafio)
ecdh_queue = queue.Queue()       # respostas ECDH de outros clientes


# --- CA: obter certificado da CA do servidor (TOFU) ---

def fetch_ca_cert():
    global ca_cert
    ca_file = 'ca.crt'
    if Path(ca_file).exists():
        with open(ca_file, 'rb') as f:
            ca_cert = cu.load_certificate(f.read())
        print("Certificado CA carregado.")
        return

    cu.send_json(sock, {'tipo': 'obter_ca'})
    resp = response_queue.get(timeout=10)
    if not resp or resp.get('tipo') != 'certificado_ca':
        raise Exception("Não foi possível obter o certificado CA do servidor.")

    ca_cert = cu.load_certificate(resp['certificado'])
    with open(ca_file, 'wb') as f:
        f.write(cu.certificate_to_pem(ca_cert))
    print("Certificado CA obtido e guardado.")


# --- Gestão de chaves de identidade ---

def load_or_generate_keys(nome):
    global private_key, public_key
    if not re.match(r'^[a-zA-Z0-9_-]{1,32}$', nome):
        print("Username inválido. Usa apenas letras, dígitos, _ e - (máx 32 caracteres).")
        sys.exit(1)
    file_name = f'{nome}.key'
    if Path(file_name).exists():
        pwd = getpass("Password da chave privada: ")
        with open(file_name, 'rb') as f:
            private_key = cu.pem_to_private(f.read(), password=pwd)
        print(f"Chave Ed25519 carregada de {file_name}")
    else:
        pwd = getpass("Define uma password para proteger a tua chave privada: ")
        private_key, _ = cu.generate_ed25519_keypair()
        with open(file_name, 'wb') as f:
            f.write(cu.private_to_pem(private_key, password=pwd))
        print(f"Nova chave Ed25519 gerada e guardada em {file_name}")
    public_key = private_key.public_key()


# --- Thread de fundo: recebe todas as mensagens do servidor ---

def receiver_thread():
    while True:
        try:
            # CORREÇÃO DE ERRO: Se o socket for fechado pela main thread (comando 'sair'),
            # esta chamada gera uma exceção, que nós capturamos para encerrar graciosamente.
            msg = cu.receive_json(sock)
        except Exception:
            break  # Sai do ciclo silenciosamente, pois a aplicação está a fechar

        if msg is None:
            print("\nLigação ao servidor terminada.")
            break

        msg_type = msg.get('tipo')

        if msg_type == 'reencaminhado':
            subtipo = msg.get('subtipo')
            rem = msg.get('remetente', '?')

            if subtipo == 'inicio_ecdh':
                pending_requests[rem] = msg.get('conteudo', {})
                print(f"\n[Chat] {rem} quer conversar contigo. Aceita com: aceitar {rem}")

            elif subtipo == 'resposta_ecdh':
                ecdh_queue.put(msg)

            elif subtipo == 'mensagem':
                display_message(msg)

            else:
                response_queue.put(msg)
        else:
            response_queue.put(msg)


def display_message(msg):
    rem = msg.get('remetente')
    if rem not in active_sessions:
        print(f"\n[{rem}] (sessão E2E não estabelecida — mensagem ignorada)")
        return
        
    sess = active_sessions[rem]
    conteudo = msg.get('conteudo', {})
    
    # Validar se a estrutura da mensagem inclui o número de sequência
    if not isinstance(conteudo, dict) or 'seq' not in conteudo:
        print(f"\n[{rem}] Mensagem ignorada (estrutura inválida ou sem sequência).")
        return
        
    seq = conteudo['seq']
    
    # MITIGAÇÃO DE REPLAY ATTACK: Rejeitar mensagens com sequências antigas ou repetidas
    if seq <= sess['rx_seq']:
        print(f"\n[ALERTA DE SEGURANÇA] Bloqueada tentativa de Replay Attack de {rem} (seq={seq}).")
        return

    try:
        dados = bytes.fromhex(conteudo['cifra'])
        seq_bytes = seq.to_bytes(8, 'big')
        
        # A decifragem com AAD valida a tag GMAC e garante o vínculo à sequência correta
        texto = cu.decrypt_message(sess['key'], dados, aad=seq_bytes).decode()
        
        # Atualiza a marca da última sequência validada com sucesso
        sess['rx_seq'] = seq 
        print(f"\n[{rem}] {texto}")
    except Exception:
        print(f"\n[{rem}] Erro ao decifrar mensagem ou falha de integridade (Tag Inválida).")


def _recv(timeout=10):
    try:
        return response_queue.get(timeout=timeout)
    except queue.Empty:
        return None


# --- Autenticação ---

def register_user(nome):
    load_or_generate_keys(nome)
    pub_pem = cu.public_to_pem(public_key).decode()
    cu.send_json(sock, {'tipo': 'registar', 'utilizador': nome, 'chave_publica': pub_pem})
    resp = _recv()
    if resp and resp.get('tipo') == 'ok':
        print(resp.get('mensagem'))
        cert_pem = resp.get('certificado', '')
        if cert_pem:
            with open(f'{nome}.crt', 'w') as f:
                f.write(cert_pem)
            print(f"Certificado guardado em {nome}.crt")
        return True
    print(f"Erro: {resp.get('mensagem') if resp else 'sem resposta'}")
    return False


def authenticate_user(nome):
    load_or_generate_keys(nome)
    cu.send_json(sock, {'tipo': 'autenticar', 'utilizador': nome})

    desafio = _recv()
    if not desafio or desafio.get('tipo') != 'desafio':
        print("Erro no desafio de autenticação.")
        return False

    nonce = bytes.fromhex(desafio['nonce'])
    sig = cu.sign_data(private_key, nonce)
    cu.send_json(sock, {'tipo': 'resposta_desafio', 'assinatura': sig.hex()})

    resp = _recv()
    if resp and resp.get('tipo') == 'ok':
        print(resp.get('mensagem'))
        return True
    print(f"Autenticação falhou: {resp.get('mensagem') if resp else 'sem resposta'}")
    return False


# --- Comandos ---

def cmd_list():
    cu.send_json(sock, {'tipo': 'listar'})
    resp = _recv()
    if resp and resp.get('tipo') == 'lista_utilizadores':
        users = resp.get('utilizadores', [])
        print("Online:", ', '.join(users) if users else '(ninguém)')
    else:
        print(f"Erro: {resp}")


def _get_verified_pubkey(dest):
    cu.send_json(sock, {'tipo': 'obter_chave', 'utilizador': dest})
    resp = _recv()
    if not resp or resp.get('tipo') != 'chave_utilizador':
        print(f"Erro ao obter chave de {dest}: {resp.get('mensagem') if resp else 'sem resposta'}")
        return None
    try:
        cert = cu.load_certificate(resp['certificado'])
        cu.verify_certificate(cert, ca_cert)
        cn = cert.subject.get_attributes_for_oid(cu.NameOID.COMMON_NAME)[0].value
        if cn != dest:
            print(f"Erro: certificado para '{cn}' mas esperado '{dest}'.")
            return None
        return cert.public_key()
    except Exception as e:
        print(f"Certificado de {dest} inválido: {e}")
        return None


def cmd_chat(dest):
    chave_pub_dest = _get_verified_pubkey(dest)
    if chave_pub_dest is None:
        return

    priv_x, pub_x = cu.generate_x25519_keypair()
    pub_x_bytes = cu.public_to_pem(pub_x)
    pending_ecdh[dest] = (priv_x, pub_x_bytes)

    sig = cu.sign_data(private_key, pub_x_bytes)

    cu.send_json(sock, {
        'tipo': 'reencaminhar',
        'destinatario': dest,
        'subtipo': 'inicio_ecdh',
        'conteudo': {'chave_efemera': pub_x_bytes.hex(), 'assinatura': sig.hex()}
    })
    ok = _recv()
    if not ok or ok.get('tipo') != 'ok':
        print(f"Erro ao enviar pedido ECDH: {ok}")
        pending_ecdh.pop(dest, None)
        return

    print(f"Pedido enviado. Aguarda que {dest} aceite ('aceitar {username}').")
    print("A aguardar resposta ECDH (timeout: 120s)...")

    try:
        resp_ecdh = ecdh_queue.get(timeout=120)
    except queue.Empty:
        print(f"Timeout. {dest} não respondeu.")
        pending_ecdh.pop(dest, None)
        return

    finalize_ecdh_initiator(dest, resp_ecdh, chave_pub_dest)


def finalize_ecdh_initiator(dest, msg, chave_pub_dest):
    conteudo = msg.get('conteudo', {})
    try:
        dest_x_bytes = bytes.fromhex(conteudo['chave_efemera'])
        sig = bytes.fromhex(conteudo['assinatura'])
        _, nossa_x_bytes = pending_ecdh[dest]
        cu.verify_signature(chave_pub_dest, sig, dest_x_bytes + nossa_x_bytes)
    except Exception as e:
        print(f"Assinatura ECDH de {dest} inválida: {e}")
        pending_ecdh.pop(dest, None)
        return

    priv_x, _ = pending_ecdh.pop(dest)
    segredo = priv_x.exchange(cu.pem_to_public(dest_x_bytes))
    info = b'chat_sessao_' + '_'.join(sorted([username, dest])).encode()
    active_sessions[dest] = {
        'key': cu.derive_key(segredo, info=info),
        'tx_seq': 1,
        'rx_seq': 0
    }
    print(f"Sessão E2E estabelecida com {dest}. Usa: msg {dest} <texto>")


def cmd_accept(dest):
    if dest not in pending_requests:
        print(f"Nenhum pedido de chat pendente de {dest}.")
        return

    chave_pub_dest = _get_verified_pubkey(dest)
    if chave_pub_dest is None:
        return
    conteudo = pending_requests.pop(dest)

    try:
        dest_x_bytes = bytes.fromhex(conteudo['chave_efemera'])
        sig = bytes.fromhex(conteudo['assinatura'])
        cu.verify_signature(chave_pub_dest, sig, dest_x_bytes)
    except Exception as e:
        print(f"Assinatura de {dest} inválida: {e}")
        return

    priv_x, pub_x = cu.generate_x25519_keypair()
    pub_x_bytes = cu.public_to_pem(pub_x)
    sig_nossa = cu.sign_data(private_key, pub_x_bytes + dest_x_bytes)

    cu.send_json(sock, {
        'tipo': 'reencaminhar',
        'destinatario': dest,
        'subtipo': 'resposta_ecdh',
        'conteudo': {'chave_efemera': pub_x_bytes.hex(), 'assinatura': sig_nossa.hex()}
    })
    ok = _recv()
    if not ok or ok.get('tipo') != 'ok':
        print(f"Erro ao enviar resposta ECDH.")
        return

    segredo = priv_x.exchange(cu.pem_to_public(dest_x_bytes))
    info = b'chat_sessao_' + '_'.join(sorted([username, dest])).encode()
    active_sessions[dest] = {
        'key': cu.derive_key(segredo, info=info),
        'tx_seq': 1,
        'rx_seq': 0
    }
    print(f"Sessão E2E estabelecida com {dest}. Usa: msg {dest} <texto>")


def cmd_send(dest, texto):
    if dest not in active_sessions:
        print(f"Sem sessão com {dest}. Usa 'chat {dest}' ou 'aceitar {dest}' primeiro.")
        return
        
    sess = active_sessions[dest]
    seq = sess['tx_seq']
    sess['tx_seq'] += 1  # Incrementa para a próxima mensagem
    
    # Passar a sequência atual como bytes AAD no AES-GCM
    seq_bytes = seq.to_bytes(8, 'big')
    ctxt = cu.encrypt_message(sess['key'], texto.encode(), aad=seq_bytes)
    
    # Envia a sequência em canal limpo e a cifra agrupadas no conteúdo
    cu.send_json(sock, {
        'tipo': 'reencaminhar',
        'destinatario': dest,
        'subtipo': 'mensagem',
        'conteudo': {'seq': seq, 'cifra': ctxt.hex()}
    })
    ok = _recv()
    if ok and ok.get('tipo') != 'ok':
        print(f"Erro ao enviar: {ok.get('mensagem')}")


# --- Loop de comandos ---

def command_loop():
    print("\nComandos disponíveis:")
    print("  listar              — lista utilizadores online")
    print("  chat <user>         — inicia sessão E2E com user")
    print("  aceitar <user>      — aceita pedido de sessão de user")
    print("  msg <user> <texto>  — envia mensagem cifrada para user")
    print("  sair                — termina a sessão\n")

    while True:
        try:
            linha = input(f"[{username}]> ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if not linha:
            continue

        partes = linha.split(' ', 2)
        cmd = partes[0].lower()

        if cmd == 'sair':
            cu.send_json(sock, {'tipo': 'sair'})
            break
        elif cmd == 'listar':
            cmd_list()
        elif cmd == 'chat' and len(partes) >= 2:
            cmd_chat(partes[1])
        elif cmd == 'aceitar' and len(partes) >= 2:
            cmd_accept(partes[1])
        elif cmd == 'msg' and len(partes) >= 3:
            cmd_send(partes[1], partes[2])
        else:
            print("Comando inválido. Usa: listar | chat <user> | aceitar <user> | msg <user> <texto> | sair")


# --- Main ---

def main():
    global sock, username

    if len(sys.argv) < 3:
        print("Uso: python3 client.py <registar|entrar> <username>")
        sys.exit(1)

    modo, username = sys.argv[1], sys.argv[2]

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER_HOST, SERVER_PORT))
    print(f"Ligado ao servidor {SERVER_HOST}:{SERVER_PORT}")

    threading.Thread(target=receiver_thread, daemon=True).start()

    fetch_ca_cert()

    if modo == 'registar':
        ok = register_user(username)
    elif modo == 'entrar':
        ok = authenticate_user(username)
    else:
        print("Modo inválido. Usa 'registar' ou 'entrar'.")
        sock.close()
        sys.exit(1)

    if not ok:
        sock.close()
        sys.exit(1)

    command_loop()
    sock.close()


if __name__ == '__main__':
    main()