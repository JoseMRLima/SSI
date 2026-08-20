import sys
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

def setup(fkey):
    chave = os.urandom(32)
    with open(fkey, 'wb') as f:
        f.write(chave)

def cifrar(fich, fkey):
    with open(fich, 'rb') as f:
        ptxt = f.read()
    with open(fkey, 'rb') as f:
        chave = f.read()

    # CBC requer que o plaintext seja múltiplo do tamanho do bloco (16 bytes)
    pad = padding.PKCS7(128).padder()
    ptxt_padded = pad.update(ptxt) + pad.finalize()

    iv = os.urandom(16)
    cifra = Cipher(algorithms.AES(chave), modes.CBC(iv))
    enc = cifra.encryptor()
    ctxt = enc.update(ptxt_padded) + enc.finalize()

    # guarda iv + criptograma
    with open(fich + '.enc', 'wb') as f:
        f.write(iv + ctxt)

def decifrar(fich, fkey):
    with open(fich, 'rb') as f:
        dados = f.read()
    with open(fkey, 'rb') as f:
        chave = f.read()

    iv = dados[:16]
    ctxt = dados[16:]

    cifra = Cipher(algorithms.AES(chave), modes.CBC(iv))
    dec = cifra.decryptor()
    ptxt_padded = dec.update(ctxt) + dec.finalize()

    unpad = padding.PKCS7(128).unpadder()
    ptxt = unpad.update(ptxt_padded) + unpad.finalize()

    with open(fich + '.dec', 'wb') as f:
        f.write(ptxt)

def main():
    if len(sys.argv) < 2:
        print("Uso: python3 cfich_aes_cbc.py <setup|enc|dec> ...")
        return

    op = sys.argv[1]

    if op == "setup":
        if len(sys.argv) != 3:
            print("Uso: python3 cfich_aes_cbc.py setup <fkey>")
            return
        setup(sys.argv[2])

    elif op == "enc":
        if len(sys.argv) != 4:
            print("Uso: python3 cfich_aes_cbc.py enc <fich> <fkey>")
            return
        cifrar(sys.argv[2], sys.argv[3])

    elif op == "dec":
        if len(sys.argv) != 4:
            print("Uso: python3 cfich_aes_cbc.py dec <fich> <fkey>")
            return
        decifrar(sys.argv[2], sys.argv[3])

    else:
        print("Operação inválida. Usa 'setup', 'enc' ou 'dec'.")

if __name__ == "__main__":
    main()
