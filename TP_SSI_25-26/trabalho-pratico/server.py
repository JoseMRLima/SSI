import socket
import threading
import json
import os
from pathlib import Path
import crypto_utils as cu

PORT = 8443
DB_FILE = 'utilizadores.json'
CA_KEY_FILE = 'ca.key'
CA_CERT_FILE = 'ca.crt'

db_lock = threading.Lock()
online_users = {}          # username -> conn
online_lock = threading.Lock()

# CA carregada no arranque
ca_key = None
ca_cert = None


# --- Persistência de utilizadores ---

def load_users_db():
    if Path(DB_FILE).exists():
        with open(DB_FILE) as f:
            return json.load(f)
    return {}

def save_users_db(users):
    with open(DB_FILE, 'w') as f:
        json.dump(users, f, indent=2)


# --- CA: carregar ou criar no arranque ---

def load_or_create_ca():
    global ca_key, ca_cert
    if Path(CA_KEY_FILE).exists() and Path(CA_CERT_FILE).exists():
        with open(CA_KEY_FILE, 'rb') as f:
            ca_key = cu.pem_to_private(f.read())
        with open(CA_CERT_FILE, 'rb') as f:
            ca_cert = cu.load_certificate(f.read())
        print("[Servidor] CA carregada.")
    else:
        ca_key, ca_cert = cu.create_ca()
        with open(CA_KEY_FILE, 'wb') as f:
            f.write(cu.private_to_pem(ca_key))
        with open(CA_CERT_FILE, 'wb') as f:
            f.write(cu.certificate_to_pem(ca_cert))
        print("[Servidor] Nova CA criada.")


# --- Tratamento de cada cliente (numa thread dedicada) ---

def handle_client(conn, addr):
    username = None
    try:
        while True:
            msg = cu.receive_json(conn)
            if msg is None:
                break

            msg_type = msg.get('tipo')

            # obter_ca não requer autenticação — é informação pública
            if msg_type == 'obter_ca':
                cu.send_json(conn, {
                    'tipo': 'certificado_ca',
                    'certificado': cu.certificate_to_pem(ca_cert).decode()
                })
            elif msg_type == 'registar':
                username = handle_register(conn, msg)
                if username:
                    deliver_offline_messages(conn, username)
            elif msg_type == 'autenticar':
                username = handle_authenticate(conn, msg)
                if username:
                    deliver_offline_messages(conn, username)
            elif not username:
                cu.send_json(conn, {'tipo': 'erro', 'mensagem': 'Não autenticado'})
            elif msg_type == 'listar':
                with online_lock:
                    cu.send_json(conn, {
                        'tipo': 'lista_utilizadores',
                        'utilizadores': list(online_users.keys())
                    })
            elif msg_type == 'obter_chave':
                handle_get_key(conn, msg)
            elif msg_type == 'reencaminhar':
                handle_forward(conn, username, msg)
            elif msg_type == 'sair':
                break
            else:
                cu.send_json(conn, {'tipo': 'erro', 'mensagem': 'Tipo desconhecido'})

    except Exception as e:
        print(f"[Servidor] Erro {addr}: {e}")
    finally:
        if username:
            with online_lock:
                online_users.pop(username, None)
            print(f"[Servidor] {username} desligou-se.")
        conn.close()


# --- Handlers dos tipos de mensagem ---

def handle_register(conn, msg):
    u = msg.get('utilizador', '').strip()
    pub_pem = msg.get('chave_publica', '')

    if not u or not pub_pem:
        cu.send_json(conn, {'tipo': 'erro', 'mensagem': 'Dados inválidos'})
        return None

    with db_lock:
        util = load_users_db()
        if u in util:
            cu.send_json(conn, {'tipo': 'erro', 'mensagem': 'Utilizador já existe'})
            return None

        # Emitir certificado X.509 para o utilizador, assinado pela CA
        user_pub = cu.pem_to_public(pub_pem)
        cert = cu.issue_certificate(ca_key, ca_cert, u, user_pub)
        cert_pem = cu.certificate_to_pem(cert).decode()

        util[u] = {'certificado': cert_pem, 'mensagens_offline': []}
        save_users_db(util)

    with online_lock:
        online_users[u] = conn

    print(f"[Servidor] Registado: {u}")
    cu.send_json(conn, {
        'tipo': 'ok',
        'mensagem': f'Registado como {u}',
        'certificado': cert_pem
    })
    return u


def handle_authenticate(conn, msg):
    u = msg.get('utilizador', '').strip()

    with db_lock:
        util = load_users_db()

    if u not in util:
        cu.send_json(conn, {'tipo': 'erro', 'mensagem': 'Utilizador não existe'})
        return None

    # Desafio: nonce aleatório que o cliente tem de assinar com a sua chave Ed25519
    nonce = os.urandom(32)
    cu.send_json(conn, {'tipo': 'desafio', 'nonce': nonce.hex()})

    resp = cu.receive_json(conn)
    if not resp or resp.get('tipo') != 'resposta_desafio':
        cu.send_json(conn, {'tipo': 'erro', 'mensagem': 'Protocolo inválido'})
        return None

    try:
        sig = bytes.fromhex(resp['assinatura'])
        # Extrair chave pública do certificado armazenado
        cert = cu.load_certificate(util[u]['certificado'])
        cu.verify_signature(cert.public_key(), sig, nonce)
    except Exception:
        cu.send_json(conn, {'tipo': 'erro', 'mensagem': 'Assinatura inválida'})
        return None

    with online_lock:
        online_users[u] = conn

    print(f"[Servidor] Autenticado: {u}")
    cu.send_json(conn, {'tipo': 'ok', 'mensagem': f'Bem-vindo, {u}!'})
    return u


def handle_get_key(conn, msg):
    u = msg.get('utilizador', '')
    with db_lock:
        util = load_users_db()
    if u not in util:
        cu.send_json(conn, {'tipo': 'erro', 'mensagem': 'Utilizador não encontrado'})
        return
    # Devolver o certificado em vez da chave pública em bruto
    cu.send_json(conn, {
        'tipo': 'chave_utilizador',
        'utilizador': u,
        'certificado': util[u]['certificado']
    })


def handle_forward(conn, sender, msg):
    """O servidor apenas roteia — não lê o conteúdo das mensagens E2E."""
    dest = msg.get('destinatario', '')
    subtipo = msg.get('subtipo', '')

    with online_lock:
        conn_dest = online_users.get(dest)

    if conn_dest is not None:
        # Destinatário online: entrega imediata
        cu.send_json(conn_dest, {
            'tipo': 'reencaminhado',
            'remetente': sender,
            'subtipo': subtipo,
            'conteudo': msg.get('conteudo', '')
        })
        cu.send_json(conn, {'tipo': 'ok'})
    elif subtipo == 'mensagem':
        # Destinatário offline: guardar mensagem cifrada para entrega posterior
        with db_lock:
            util = load_users_db()
            if dest not in util:
                cu.send_json(conn, {'tipo': 'erro', 'mensagem': f'{dest} não existe'})
                return
            util[dest]['mensagens_offline'].append({
                'remetente': sender,
                'subtipo': subtipo,
                'conteudo': msg.get('conteudo', '')
            })
            save_users_db(util)
        print(f"[Servidor] Mensagem de {sender} para {dest} guardada (offline).")
        cu.send_json(conn, {'tipo': 'ok', 'mensagem': f'{dest} está offline. Mensagem guardada.'})
    else:
        # ECDH requer ambos online — não faz sentido guardar offline
        cu.send_json(conn, {'tipo': 'erro', 'mensagem': f'{dest} não está online'})


def deliver_offline_messages(conn, username):
    """Entrega mensagens pendentes ao utilizador que acabou de ligar."""
    with db_lock:
        util = load_users_db()
        msgs = util[username].get('mensagens_offline', [])
        if not msgs:
            return
        util[username]['mensagens_offline'] = []
        save_users_db(util)

    print(f"[Servidor] A entregar {len(msgs)} mensagem(ns) offline a {username}.")
    for m in msgs:
        cu.send_json(conn, {
            'tipo': 'reencaminhado',
            'remetente': m['remetente'],
            'subtipo': m['subtipo'],
            'conteudo': m['conteudo']
        })


# --- Main ---

def main():
    load_or_create_ca()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', PORT))
    s.listen()
    print(f"[Servidor] À escuta na porta {PORT}...")

    while True:
        conn, addr = s.accept()
        print(f"[Servidor] Ligação de {addr}")
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == '__main__':
    main()
