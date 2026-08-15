import sys
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def derivar_chave(frase, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return kdf.derive(frase)

def cifrar(fich):
    with open(fich, 'rb') as f:
        ptxt = f.read()

    frase = input("Frase-chave: ").encode()
    salt = os.urandom(16)
    chave = derivar_chave(frase, salt)

    # GCM recomenda nonce de 12 bytes
    nonce = os.urandom(12)
    gcm = AESGCM(chave)
    ctxt = gcm.encrypt(nonce, ptxt, None)

    # guarda salt + nonce + criptograma (inclui tag GCM nos últimos 16 bytes)
    with open(fich + '.enc', 'wb') as f:
        f.write(salt + nonce + ctxt)

def decifrar(fich):
    with open(fich, 'rb') as f:
        dados = f.read()

    frase = input("Frase-chave: ").encode()
    salt = dados[:16]
    nonce = dados[16:28]
    ctxt = dados[28:]

    chave = derivar_chave(frase, salt)
    gcm = AESGCM(chave)

    try:
        ptxt = gcm.decrypt(nonce, ctxt, None)
    except Exception:
        print("Erro: autenticação falhou. O ficheiro pode ter sido adulterado.")
        return

    with open(fich + '.dec', 'wb') as f:
        f.write(ptxt)

def main():
    if len(sys.argv) != 3:
        print("Uso: python3 pbenc_aes_gcm.py <enc|dec> <ficheiro>")
        return

    op = sys.argv[1]
    fich = sys.argv[2]

    if op == "enc":
        cifrar(fich)
    elif op == "dec":
        decifrar(fich)
    else:
        print("Operação inválida. Usa 'enc' ou 'dec'.")

if __name__ == "__main__":
    main()
