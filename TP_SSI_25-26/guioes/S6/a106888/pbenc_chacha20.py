import sys
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def derivar_chave(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return kdf.derive(password)

def cifrar(fich):
    with open(fich, 'rb') as f:
        ptxt = f.read()

    frase = input("Frase-chave: ").encode()
    salt = os.urandom(16)
    chave = derivar_chave(frase, salt)

    nonce = os.urandom(16)
    cifra = Cipher(algorithms.ChaCha20(chave, nonce), mode=None)
    enc = cifra.encryptor()
    ctxt = enc.update(ptxt)

    # guarda salt + nonce + criptograma
    with open(fich + '.enc', 'wb') as f:
        f.write(salt + nonce + ctxt)

def decifrar(fich):
    with open(fich, 'rb') as f:
        dados = f.read()

    frase = input("Frase-chave: ").encode()
    salt = dados[:16]
    nonce = dados[16:32]
    ctxt = dados[32:]

    chave = derivar_chave(frase, salt)

    cifra = Cipher(algorithms.ChaCha20(chave, nonce), mode=None)
    dec = cifra.decryptor()
    ptxt = dec.update(ctxt)

    with open(fich + '.dec', 'wb') as f:
        f.write(ptxt)

def main():
    if len(sys.argv) != 3:
        print("Uso: python3 pbenc_chacha20.py <enc|dec> <ficheiro>")
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
