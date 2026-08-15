import sys
import itertools

# frequências aproximadas das letras em português
FREQ_PT = {
    'A': 14.63, 'B': 1.04, 'C': 3.88, 'D': 4.99, 'E': 13.01, 'F': 1.02,
    'G': 1.30,  'H': 1.28, 'I': 6.18, 'J': 0.37, 'K': 0.02, 'L': 2.78,
    'M': 4.74,  'N': 4.46, 'O': 9.73, 'P': 2.52, 'Q': 1.20, 'R': 6.53,
    'S': 6.80,  'T': 4.34, 'U': 3.64, 'V': 1.57, 'W': 0.04, 'X': 0.45,
    'Y': 0.01,  'Z': 0.47
}

def decifrar(criptograma, chave):
    resultado = []
    for i, c in enumerate(criptograma):
        if c.isalpha():
            deslocamento = ord(chave[i % len(chave)]) - ord('A')
            novo_ascii = (ord(c.upper()) - ord('A') - deslocamento) % 26 + ord('A')
            resultado.append(chr(novo_ascii))
    return "".join(resultado)

def main():
    if len(sys.argv) < 4:
        print("Uso: python3 vigenere_attack.py <tamanho_chave> <criptograma> <palavra1> [palavra2 ...]")
        return

    try:
        k = int(sys.argv[1])
    except ValueError:
        print("O tamanho da chave deve ser um número inteiro.")
        return

    criptograma = sys.argv[2].upper()
    palavras_alvo = [p.upper() for p in sys.argv[3:]]

    criptograma_limpo = "".join([c for c in criptograma if c.isalpha()])

    # divide o criptograma em k fatias, cada uma cifrada com uma letra da chave
    fatias = ["" for _ in range(k)]
    for i, c in enumerate(criptograma_limpo):
        fatias[i % k] += c

    # para cada fatia, ordena os 26 deslocamentos pelo score de frequência
    possiveis_deslocamentos = []
    for fatia in fatias:
        pontuacoes = []
        for deslocamento in range(26):
            score = 0
            for c in fatia:
                letra_dec = chr((ord(c) - ord('A') - deslocamento) % 26 + ord('A'))
                score += FREQ_PT.get(letra_dec, 0)
            pontuacoes.append((score, deslocamento))

        pontuacoes.sort(reverse=True, key=lambda x: x[0])
        possiveis_deslocamentos.append([d for _, d in pontuacoes])

    # testa combinações da mais provável para a menos provável
    for combinacao in itertools.product(*possiveis_deslocamentos):
        chave = "".join([chr(d + ord('A')) for d in combinacao])
        texto_decifrado = decifrar(criptograma_limpo, chave)

        for palavra in palavras_alvo:
            if palavra in texto_decifrado:
                print(chave)
                print(texto_decifrado)
                return

if __name__ == "__main__":
    main()
