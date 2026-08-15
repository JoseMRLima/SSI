import sys

def preproc(texto):
    l = []
    for c in texto:
        if c.isalpha():
            l.append(c.upper())
    return "".join(l)

def main():
    if len(sys.argv) != 4:
        print("Uso: python3 vigenere.py <enc|dec> <chave> <mensagem>")
        return

    op = sys.argv[1].lower()
    chave = preproc(sys.argv[2])
    msg = sys.argv[3]

    if not chave:
        print("A chave deve conter pelo menos uma letra válida.")
        return

    if op not in ('enc', 'dec'):
        print("Operação inválida. Usa 'enc' para cifrar ou 'dec' para decifrar.")
        return

    msg_limpa = preproc(msg)
    resultado = []

    for i, c in enumerate(msg_limpa):
        letra_chave = chave[i % len(chave)]
        deslocamento = ord(letra_chave) - ord('A')

        if op == 'dec':
            deslocamento = -deslocamento

        novo_ascii = (ord(c) - ord('A') + deslocamento) % 26 + ord('A')
        resultado.append(chr(novo_ascii))

    print("".join(resultado))

if __name__ == "__main__":
    main()
