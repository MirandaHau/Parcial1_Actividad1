from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import hashlib
import Crypto.Util.number as number


def generar_claves():
    # Generamos dos primos de 1024 bits
    p = number.getPrime(1024)
    q = number.getPrime(1024)
    n = p * q
    e = 65537  # Número de Fermat 4
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)  # Inverso modular de e en phi(n)

    # Construimos la clave RSA
    private_key = RSA.construct((n, e, d))
    public_key = RSA.construct((n, e))

    print("Clave privada generada:", private_key.export_key().decode()[:100], "...")
    print("Clave pública generada:", public_key.export_key().decode()[:100], "...")
    return private_key.export_key(), public_key.export_key()


def dividir_mensaje(mensaje, tamano=128):
    partes = [mensaje[i:i + tamano] for i in range(0, len(mensaje), tamano)]
    print(f"Mensaje dividido en {len(partes)} partes.")
    return partes


def cifrar_mensaje(mensaje, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    bloques = dividir_mensaje(mensaje)
    mensajes_cifrados = [cipher.encrypt(bloque.encode()) for bloque in bloques]
    print("Mensaje cifrado en bloques.")
    return mensajes_cifrados


def descifrar_mensaje(mensajes_cifrados, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    bloques_descifrados = [cipher.decrypt(bloque).decode() for bloque in mensajes_cifrados]
    print("Mensaje descifrado correctamente.")
    return "".join(bloques_descifrados)


def calcular_hash(mensaje):
    hash_value = hashlib.sha256(mensaje.encode()).hexdigest()
    print("Hash generado:", hash_value)
    return hash_value


# 1. Generación de claves
private_key, public_key = generar_claves()

# 2. Creación del mensaje de 1050 caracteres
mensaje_original = "A" * 1050  # Mensaje de prueba
print("Mensaje original:", mensaje_original[:100], "...")
hash_original = calcular_hash(mensaje_original)

# 3. Cifrado del mensaje por Alice
mensajes_cifrados = cifrar_mensaje(mensaje_original, public_key)

# 4. Descifrado del mensaje por Bob
mensaje_descifrado = descifrar_mensaje(mensajes_cifrados, private_key)
print("Mensaje descifrado:", mensaje_descifrado[:100], "...")
hash_descifrado = calcular_hash(mensaje_descifrado)

# 5. Comparación de hashes
if hash_original == hash_descifrado:
    print("El mensaje es auténtico y no ha sido modificado.")
else:
    print("¡Advertencia! El mensaje ha sido alterado.")