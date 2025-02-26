import Crypto.Util.number
import hashlib

e = 65537

# Generación de dos números primos de 1024 bits
pA = Crypto.Util.number.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)
qA = Crypto.Util.number.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)

print(f'\nNúmeros primos de Alice: {pA} \n y {qA}')

# Cálculo de la llave pública de Alice (nA)
nA = pA * qA
print(f'\nLlave pública de Alice (nA): {nA}')

# Cálculo de phi de Alice
phiA = (pA - 1) * (qA - 1)
print(f'\nPhi de Alice: {phiA}')

# Cálculo de la llave privada de Alice
dA = Crypto.Util.number.inverse(e, phiA)
print(f'\nLlave privada de Alice: {dA}')

# Creación del mensaje de prueba (1050 caracteres)
mensaje_original = "A" * 1050  # Mensaje de prueba
print("Mensaje original:", mensaje_original[:100], "...")

# Hash del mensaje original (h(M))
h1 = int.from_bytes(hashlib.sha256(mensaje_original.encode('utf-8')).digest(), byteorder='big')
print('\nMensaje hasheado: ', hex(h1))

# Dividir el mensaje en fragmentos de 128 caracteres
mensaje_dividido = [mensaje_original[i:i+128] for i in range(0, len(mensaje_original), 128)]

# Cifrado del mensaje por Alice (utilizando RSA)
mensajes_cifrados = []
for fragmento in mensaje_dividido:
    m = int.from_bytes(fragmento.encode('utf-8'), byteorder='big')
    c = pow(m, e, nA)  # Cifrado: c = m^e mod n
    mensajes_cifrados.append(c)

# Mostrar los fragmentos cifrados
for i, cifrado in enumerate(mensajes_cifrados):
    print(f'\nFragmento {i+1} cifrado: {cifrado}')

# Descifrado del mensaje por Bob (utilizando RSA)
mensajes_descifrados = []
for c in mensajes_cifrados:
    m_descifrado = pow(c, dA, nA)  # Descifrado: m = c^d mod n
    mensajes_descifrados.append(m_descifrado)

# Convertir los fragmentos descifrados de enteros a texto
fragmentos_descifrados = [int.to_bytes(d, length=(d.bit_length() + 7) // 8, byteorder='big').decode('utf-8', errors='ignore') for d in mensajes_descifrados]

# Mostrar los fragmentos descifrados
print("\nMensaje descifrado:")
mensaje_descifrado = "".join(fragmentos_descifrados)
print(mensaje_descifrado[:100], "...")

# Hash del mensaje descifrado (h(M'))
h2 = int.from_bytes(hashlib.sha256(mensaje_descifrado.encode('utf-8')).digest(), byteorder='big')
print('\nMensaje hasheado después de descifrar: ', hex(h2))

# Verificación de si los hashes coinciden
verificacion = (h1 == h2)
print('\n¿Los mensajes son iguales después de descifrar? ', verificacion)