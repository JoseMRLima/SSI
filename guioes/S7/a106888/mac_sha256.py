import sys
import os
import hashlib

def setup(fkey):
    chave = os.urandom(32)
    with open(fkey, 'wb') as f:
        f.write(chave)

def calcular_mac(fich, fkey):
    with open(fich, 'rb') as f:
        msg = f.read()
    with open(fkey, 'rb') as f:
        chave = f.read()
    # prefix-MAC: H(k || m)
    mac = hashlib.sha256(chave + msg).digest()
    with open(fich + '.mac', 'wb') as f:
        f.write(mac)

def verificar(fich, fkey):
    with open(fich, 'rb') as f:
        msg = f.read()
    with open(fkey, 'rb') as f:
        chave = f.read()
    with open(fich + '.mac', 'rb') as f:
        mac_guardado = f.read()
    mac_calc = hashlib.sha256(chave + msg).digest()
    print(mac_calc == mac_guardado)

def main():
    if len(sys.argv) < 2:
        print("Uso: python3 mac_sha256.py <setup|mac|ver> ...")
        return

    op = sys.argv[1]

    if op == "setup":
        if len(sys.argv) != 3:
            print("Uso: python3 mac_sha256.py setup <fkey>")
            return
        setup(sys.argv[2])

    elif op == "mac":
        if len(sys.argv) != 4:
            print("Uso: python3 mac_sha256.py mac <fich> <fkey>")
            return
        calcular_mac(sys.argv[2], sys.argv[3])

    elif op == "ver":
        if len(sys.argv) != 4:
            print("Uso: python3 mac_sha256.py ver <fich> <fkey>")
            return
        verificar(sys.argv[2], sys.argv[3])

    else:
        print("Operação inválida. Usa 'setup', 'mac' ou 'ver'.")

if __name__ == "__main__":
    main()
