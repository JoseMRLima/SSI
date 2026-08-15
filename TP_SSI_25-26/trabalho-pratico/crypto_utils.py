import os
import json
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, SECP256R1, ECDSA
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509
from cryptography.x509.oid import NameOID


# --- Geração de chaves ---

def generate_ed25519_keypair():
    """Par Ed25519 para identidade (assinatura)."""
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()

def generate_x25519_keypair():
    """Par X25519 efémero para ECDH."""
    priv = X25519PrivateKey.generate()
    return priv, priv.public_key()


# --- Serialização ---

def public_to_pem(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def pem_to_public(pem_data):
    if isinstance(pem_data, str):
        pem_data = pem_data.encode()
    return serialization.load_pem_public_key(pem_data)

def private_to_pem(private_key, password=None):
    enc = (serialization.BestAvailableEncryption(password.encode())
           if password else serialization.NoEncryption())
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc
    )

def pem_to_private(pem_data, password=None):
    if isinstance(pem_data, str):
        pem_data = pem_data.encode()
    pwd = password.encode() if password else None
    return serialization.load_pem_private_key(pem_data, password=pwd)


# --- Assinatura Ed25519 ---

def sign_data(private_key, data):
    return private_key.sign(data)

def verify_signature(public_key, signature, data):
    """Lança exceção se a assinatura for inválida."""
    public_key.verify(signature, data)


# --- Derivação de chave (HKDF) ---

def derive_key(secret, info=b'chat_sessao'):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info
    ).derive(secret)


# --- Cifragem simétrica (AES-256-GCM) ---

def encrypt_message(key, message, aad=None):
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, message, aad)

def decrypt_message(key, data, aad=None):
    return AESGCM(key).decrypt(data[:12], data[12:], aad)


# --- Framing TCP (prefixo de tamanho 4 bytes big-endian) ---

# Limite máximo de tamanho do payload (10 MB) para prevenir ataques OOM
MAX_MSG_SIZE = 10 * 1024 * 1024

def send_message(sock, data):
    sock.sendall(len(data).to_bytes(4, 'big') + data)

def receive_message(sock):
    size_bytes = _receive_exact(sock, 4)
    if not size_bytes:
        return None
    
    msg_size = int.from_bytes(size_bytes, 'big')
    
    # Validação de segurança: bloquear pacotes gigantes
    if msg_size > MAX_MSG_SIZE:
        raise ValueError(f"Ataque detetado ou erro de protocolo: payload de {msg_size} bytes excede o limite de {MAX_MSG_SIZE} bytes.")
        
    return _receive_exact(sock, msg_size)

def _receive_exact(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf

def send_json(sock, obj):
    send_message(sock, json.dumps(obj).encode())

def receive_json(sock):
    data = receive_message(sock)
    return json.loads(data.decode()) if data else None


# --- PKI: Autoridade de Certificação (CA) ---

def create_ca():
    """Gera par de chaves EC P-256 e certificado CA self-signed."""
    ca_key = generate_private_key(SECP256R1())
    nome = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SSI-Chat-CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(nome)
        .issuer_name(nome)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    return ca_key, ca_cert

def issue_certificate(ca_key, ca_cert, username, user_pub_key):
    """Emite certificado X.509 para um utilizador, assinado pela CA."""
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, username)]))
        .issuer_name(ca_cert.subject)
        .public_key(user_pub_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    return cert

def verify_certificate(cert, ca_cert):
    """Verifica que o certificado foi assinado pela CA. Lança exceção se inválido."""
    ca_pub = ca_cert.public_key()
    ca_pub.verify(cert.signature, cert.tbs_certificate_bytes, ECDSA(cert.signature_hash_algorithm))

def load_certificate(pem):
    if isinstance(pem, str):
        pem = pem.encode()
    return x509.load_pem_x509_certificate(pem)

def certificate_to_pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)