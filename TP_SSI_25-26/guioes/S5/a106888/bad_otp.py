import sys
import random

def bad_prng(n):
    """ an INSECURE pseudo-random number generator """
    random.seed(random.randbytes(2))
    return random.randbytes(n)

def setup(n_bytes, ficheiro_chave):
    chave = bad_prng(n_bytes)
    with open(ficheiro_chave, 'wb') as f:
        f.write(chave)

def cifrar(ficheiro_ptxt, ficheiro_chave):
    with open(ficheiro_ptxt, 'rb') as f:
        ptxt = f.read()
    with open(ficheiro_chave, 'rb') as f:
        chave = f.read()
    ctxt = bytes(p ^ k for p, k in zip(ptxt, chave))
    with open(ficheiro_ptxt + '.enc', 'wb') as f:
        f.write(ctxt)

def decifrar(ficheiro_ctxt, ficheiro_chave):
    with open(ficheiro_ctxt, 'rb') as f:
        ctxt = f.read()
    with open(ficheiro_chave, 'rb') as f:
        chave = f.read()
    ptxt = bytes(c ^ k for c, k in zip(ctxt, chave))
    with open(ficheiro_ctxt + '.dec', 'wb') as f:
        f.write(ptxt)

def main():
    if len(sys.argv) < 2:
        print("Uso: python3 bad_otp.py <setup|enc|dec> ...")
        return

    op = sys.argv[1]

    if op == "setup":
        if len(sys.argv) != 4:
            print("Uso: python3 bad_otp.py setup <n_bytes> <ficheiro_chave>")
            return
        setup(int(sys.argv[2]), sys.argv[3])

    elif op == "enc":
        if len(sys.argv) != 4:
            print("Uso: python3 bad_otp.py enc <ficheiro_ptxt> <ficheiro_chave>")
            return
        cifrar(sys.argv[2], sys.argv[3])

    elif op == "dec":
        if len(sys.argv) != 4:
            print("Uso: python3 bad_otp.py dec <ficheiro_ctxt> <ficheiro_chave>")
            return
        decifrar(sys.argv[2], sys.argv[3])

    else:
        print("Operação inválida. Usa 'setup', 'enc' ou 'dec'.")

if __name__ == "__main__":
    main()
