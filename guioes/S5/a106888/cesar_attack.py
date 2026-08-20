import sys

def decifrar(criptograma, deslocamento):
    resultado = []
    for c in criptograma:
        if c.isalpha():
            novo_ascii = (ord(c.upper()) - ord('A') - deslocamento) % 26 + ord('A')
            resultado.append(chr(novo_ascii))
    return "".join(resultado)

def main():
    if len(sys.argv) < 3:
        print("Uso: python3 cesar_attack.py <criptograma> <palavra1> [palavra2 ...]")
        return

    criptograma = sys.argv[1]
    palavras_alvo = [p.upper() for p in sys.argv[2:]]

    # tenta os 26 deslocamentos possíveis
    for deslocamento in range(26):
        texto_decifrado = decifrar(criptograma, deslocamento)

        for palavra in palavras_alvo:
            if palavra in texto_decifrado:
                chave_usada = chr(deslocamento + ord('A'))
                print(chave_usada)
                print(texto_decifrado)
                return

if __name__ == "__main__":
    main()
