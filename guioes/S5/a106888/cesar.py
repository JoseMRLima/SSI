import sys

def preproc(texto):
    l = []
    for c in texto:
        if c.isalpha():
            l.append(c.upper())
    return "".join(l)

def main():
    if len(sys.argv) != 4:
        print("Uso: python3 cesar.py <enc|dec> <chave> <mensagem>")
        return

    op = sys.argv[1].lower()
    chave = sys.argv[2].upper()
    msg = sys.argv[3]

    deslocamento = ord(chave) - ord('A')

    if op == 'dec':
        deslocamento = -deslocamento
    elif op != 'enc':
        print("Operação inválida. Usa 'enc' para cifrar ou 'dec' para decifrar.")
        return

    msg_limpa = preproc(msg)
    resultado = []

    for c in msg_limpa:
        novo_ascii = (ord(c) - ord('A') + deslocamento) % 26 + ord('A')
        resultado.append(chr(novo_ascii))

    print("".join(resultado))

if __name__ == "__main__":
    main()
