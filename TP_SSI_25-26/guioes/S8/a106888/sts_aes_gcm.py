from multiprocessing import Process, Pipe
from cryptography.hazmat.primitives.asymmetric import dh, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509
import os

p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2

def mkpair(x, y):
    len_x = len(x)
    len_x_bytes = len_x.to_bytes(2, "little")
    return len_x_bytes + x + y

def unpair(xy):
    len_x = int.from_bytes(xy[:2], "little")
    x = xy[2 : len_x + 2]
    y = xy[len_x + 2 :]
    return x, y

def derivar_chave(segredo):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'sts_aes_gcm'
    ).derive(segredo)

def assinar(chave_privada, dados):
    return chave_privada.sign(
        dados,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def verificar_assinatura(chave_publica, assinatura, dados):
    chave_publica.verify(
        assinatura,
        dados,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def verificar_certificado(cert, cert_ca):
    cert_ca.public_key().verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm
    )

def alice_process(conn):
    with open('Alice.key', 'rb') as f:
        chave_privada_rsa = serialization.load_pem_private_key(f.read(), password=None)
    with open('Alice.crt', 'rb') as f:
        cert_alice = x509.load_pem_x509_certificate(f.read())
    with open('CA.crt', 'rb') as f:
        cert_ca = x509.load_pem_x509_certificate(f.read())

    parametros = dh.DHParameterNumbers(p, g).parameters()
    chave_privada_dh = parametros.generate_private_key()
    alice_pub_bytes = chave_privada_dh.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # 1. Alice → Bob: g^x
    conn.send(alice_pub_bytes)

    # 2. Bob → Alice: g^y, SigB(g^y, g^x), CertB
    dados = conn.recv()
    bob_pub_bytes, resto = unpair(dados)
    sig_bob, cert_bob_bytes = unpair(resto)

    cert_bob = x509.load_pem_x509_certificate(cert_bob_bytes)
    verificar_certificado(cert_bob, cert_ca)
    verificar_assinatura(cert_bob.public_key(), sig_bob, bob_pub_bytes + alice_pub_bytes)

    # 3. Alice → Bob: SigA(g^x, g^y), CertA
    sig_alice = assinar(chave_privada_rsa, alice_pub_bytes + bob_pub_bytes)
    cert_alice_bytes = cert_alice.public_bytes(serialization.Encoding.PEM)
    conn.send(mkpair(sig_alice, cert_alice_bytes))

    # 4. Segredo partilhado + derivar chave AES
    bob_pub_dh = serialization.load_pem_public_key(bob_pub_bytes)
    segredo = chave_privada_dh.exchange(bob_pub_dh)
    chave_aes = derivar_chave(segredo)
    print(f"[Alice] K = {segredo.hex()}")

    aesgcm = AESGCM(chave_aes)
    nonce = os.urandom(12)
    mensagem = b"Ola Bob, sou a Alice autenticada!"
    ctxt = aesgcm.encrypt(nonce, mensagem, None)
    conn.send(nonce + ctxt)
    print(f"[Alice] Mensagem cifrada enviada.")

def bob_process(conn):
    with open('Bob.key', 'rb') as f:
        chave_privada_rsa = serialization.load_pem_private_key(f.read(), password=None)
    with open('Bob.crt', 'rb') as f:
        cert_bob = x509.load_pem_x509_certificate(f.read())
    with open('CA.crt', 'rb') as f:
        cert_ca = x509.load_pem_x509_certificate(f.read())

    parametros = dh.DHParameterNumbers(p, g).parameters()
    chave_privada_dh = parametros.generate_private_key()
    bob_pub_bytes = chave_privada_dh.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # 1. Alice → Bob: g^x
    alice_pub_bytes = conn.recv()

    # 2. Bob → Alice: g^y, SigB(g^y, g^x), CertB
    sig_bob = assinar(chave_privada_rsa, bob_pub_bytes + alice_pub_bytes)
    cert_bob_bytes = cert_bob.public_bytes(serialization.Encoding.PEM)
    conn.send(mkpair(bob_pub_bytes, mkpair(sig_bob, cert_bob_bytes)))

    # 3. Alice → Bob: SigA(g^x, g^y), CertA
    dados = conn.recv()
    sig_alice, cert_alice_bytes = unpair(dados)

    cert_alice = x509.load_pem_x509_certificate(cert_alice_bytes)
    verificar_certificado(cert_alice, cert_ca)
    verificar_assinatura(cert_alice.public_key(), sig_alice, alice_pub_bytes + bob_pub_bytes)

    # 4. Segredo partilhado + derivar chave AES
    alice_pub_dh = serialization.load_pem_public_key(alice_pub_bytes)
    segredo = chave_privada_dh.exchange(alice_pub_dh)
    chave_aes = derivar_chave(segredo)
    print(f"[Bob]   K = {segredo.hex()}")

    dados = conn.recv()
    nonce, ctxt = dados[:12], dados[12:]
    aesgcm = AESGCM(chave_aes)
    ptxt = aesgcm.decrypt(nonce, ctxt, None)
    print(f"[Bob]   Mensagem decifrada: {ptxt.decode()}")

if __name__ == '__main__':
    parent_conn, child_conn = Pipe()
    p1 = Process(target=alice_process, args=(parent_conn,))
    p2 = Process(target=bob_process, args=(child_conn,))
    p1.start(); p2.start()
    p1.join(); p2.join()
