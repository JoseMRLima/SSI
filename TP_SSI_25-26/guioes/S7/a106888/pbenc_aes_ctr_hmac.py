import sys
import os
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def derivar_chaves(frase, salt):
    # deriva 64 bytes: primeiros 32 para a cifra, últimos 32 para o MAC
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        iterations=480000,
    )
    material = kdf.derive(frase)
    return material[:32], material[32:]

def cifrar(fich):
    with open(fich, 'rb') as f:
        ptxt = f.read()

    frase = input("Frase-chave: ").encode()
    salt = os.urandom(16)
    chave_cifra, chave_mac = derivar_chaves(frase, salt)

    nonce = os.urandom(16)
    cifra = Cipher(algorithms.AES(chave_cifra), modes.CTR(nonce))
    enc = cifra.encryptor()
    ctxt = enc.update(ptxt) + enc.finalize()

    # encrypt-then-MAC: o MAC é calculado sobre o criptograma
    tag = hmac.new(chave_mac, ctxt, hashlib.sha256).digest()

    # guarda salt + nonce + tag + criptograma
    with open(fich + '.enc', 'wb') as f:
        f.write(salt + nonce + tag + ctxt)

def decifrar(fich):
    with open(fich, 'rb') as f:
        dados = f.read()

    frase = input("Frase-chave: ").encode()
    salt = dados[:16]
    nonce = dados[16:32]
    tag_guardada = dados[32:64]
    ctxt = dados[64:]

    chave_cifra, chave_mac = derivar_chaves(frase, salt)

    # verificar MAC antes de decifrar
    tag_calc = hmac.new(chave_mac, ctxt, hashlib.sha256).digest()
    if not hmac.compare_digest(tag_calc, tag_guardada):
        print("Erro: MAC inválido. O ficheiro pode ter sido adulterado.")
        return

    cifra = Cipher(algorithms.AES(chave_cifra), modes.CTR(nonce))
    dec = cifra.decryptor()
    ptxt = dec.update(ctxt) + dec.finalize()

    with open(fich + '.dec', 'wb') as f:
        f.write(ptxt)

def main():
    if len(sys.argv) != 3:
        print("Uso: python3 pbenc_aes_ctr_hmac.py <enc|dec> <ficheiro>")
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
