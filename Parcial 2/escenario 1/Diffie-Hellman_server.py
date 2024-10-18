import socket
import hashlib
import random
from Crypto.Cipher import Salsa20
from Crypto.Random import get_random_bytes
import json

# Cargar los parámetros desde el archivo JSON
with open('parameters.json', 'r') as f:
    parameters = json.load(f)["parameters"]

# Parametros
param = parameters[0]  # Cambiar parameters[#] para usar los parametros de su preferencia
p = param['p']
g = param['g']

# Función Diffie-Hellman para generar la clave pública
def diffie_hellman_generate_keypair(p, g):
    private_key = random.randint(2, p - 2)  # Clave privada aleatoria
    public_key = pow(g, private_key, p)  # Clave pública g^a mod p
    return private_key, public_key

# Función para calcular el secreto compartido
def diffie_hellman_shared_secret(private_key, public_key_other, p):
    shared_secret = pow(public_key_other, private_key, p)
    return shared_secret

# Función para derivar una llave simétrica usando SHA-256
def derive_key(shared_secret):
    shared_secret_bytes = str(shared_secret).encode()
    key = hashlib.sha256(shared_secret_bytes).digest()
    return key

def server():
    # Crear el servidor
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(1)

    print("Servidor: Esperando conexión del cliente...")
    client_socket, addr = server_socket.accept()
    print(f"Servidor: Conectado a {addr}")

    # Inicializar contadores de bytes
    total_bytes_sent = 0
    total_bytes_received = 0

    # Enviar los valores de g y p al cliente
    params = f"{g},{p}".encode()
    client_socket.send(params)
    total_bytes_sent += len(params)
    print(f"Servidor: Parámetros g={g} y p={p} enviados al cliente")

    # Generar el par de claves Diffie-Hellman
    private_key, public_key = diffie_hellman_generate_keypair(p, g)

    # Recibir la clave pública del cliente
    public_key_client = int(client_socket.recv(1024).decode())
    total_bytes_received += len(str(public_key_client).encode())
    print(f"Servidor: Clave pública del cliente recibida: {public_key_client}")

    # Enviar la clave pública al cliente
    public_key_bytes = str(public_key).encode()
    client_socket.send(public_key_bytes)
    total_bytes_sent += len(public_key_bytes)

    # Calcular el secreto compartido
    shared_secret = diffie_hellman_shared_secret(private_key, public_key_client, p)
    print(f"Servidor: Secreto compartido calculado: {shared_secret}")

    # Derivar la llave simétrica
    key = derive_key(shared_secret)
    print(f"Servidor: Llave simétrica derivada: {key.hex()}")

    # Ciclo de recepción y descifrado de 100 mensajes
    for i in range(1):
        # Recibir el mensaje cifrado del cliente
        ciphertext = client_socket.recv(1024)
        total_bytes_received += len(ciphertext)
        nonce = ciphertext[:8]
        ciphertext = ciphertext[8:]

        # Descifrar el mensaje
        cipher = Salsa20.new(key=key, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        print(f"Servidor: ({i + 1}/100) Mensaje del cliente descifrado: {plaintext.decode()}")

    # Cerrar la conexión
    client_socket.close()
    server_socket.close()

    # Mostrar estadísticas de transmisión
    print(f"Total de bytes enviados: {total_bytes_sent}")
    print(f"Total de bytes recibidos: {total_bytes_received}")

if __name__ == "__main__":
    server()
