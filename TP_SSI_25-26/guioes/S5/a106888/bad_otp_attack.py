import sys
import random

def tentar_seed(seed_bytes, tamanho_chave, ctxt, palavras):
    random.seed(seed_bytes)
    chave = random.randbytes(tamanho_chave)
    ptxt = bytes(c ^ k for c, k in zip(ctxt, chave))
    try:
        texto = ptxt.decode('utf-8')
        if any(p in texto.lower() for p in palavras):
            return texto
    except UnicodeDecodeError:
        pass
    return None

def main():
    if len(sys.argv) < 4:
        print("Uso: python3 bad_otp_attack.py <tamanho_chave> <ficheiro_ctxt> <palavra1> [palavra2 ...]")
        return

    tamanho_chave = int(sys.argv[1])
    ficheiro_ctxt = sys.argv[2]
    palavras = [p.lower() for p in sys.argv[3:]]

    with open(ficheiro_ctxt, 'rb') as f:
        ctxt = f.read()

    # espaço de seeds: 2 bytes -> 65536 possibilidades
    for s in range(65536):
        resultado = tentar_seed(s.to_bytes(2, 'big'), tamanho_chave, ctxt, palavras)
        if resultado:
            print(resultado, end="")
            return

if __name__ == "__main__":
    main()
