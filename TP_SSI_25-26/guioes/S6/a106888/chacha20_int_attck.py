import sys

def main():
    if len(sys.argv) != 5:
        print("Uso: python3 chacha20_int_attck.py <fctxt> <pos> <ptxtAtPos> <newPtxtAtPos>")
        return

    fctxt = sys.argv[1]
    pos = int(sys.argv[2])
    ptxt_na_pos = sys.argv[3].encode()
    novo_ptxt_na_pos = sys.argv[4].encode()

    with open(fctxt, 'rb') as f:
        dados = f.read()

    nonce = dados[:16]
    ctxt = bytearray(dados[16:])

    # numa cifra de stream, ctxt[i] = ptxt[i] XOR keystream[i]
    # para substituir ptxt_na_pos por novo_ptxt_na_pos basta fazer XOR com ambos
    for i, (p, n) in enumerate(zip(ptxt_na_pos, novo_ptxt_na_pos)):
        ctxt[pos + i] ^= p ^ n

    with open(fctxt + '.attck', 'wb') as f:
        f.write(nonce + bytes(ctxt))

if __name__ == "__main__":
    main()
