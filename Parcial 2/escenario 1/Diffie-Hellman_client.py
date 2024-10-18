import socket
import hashlib
import random
import time  # Importar para agregar el delay
from Crypto.Cipher import Salsa20
import json

# Cargar los parámetros desde el archivo JSON
with open('parameters.json', 'r') as f:
    parameters = json.load(f)["parameters"]

#Parametros
#param = parameters[2] # Cambiar parameters[#] para usar los parametros de su preferencia
#p = param['p']
#g = param['g']

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

def client():
    # Crear el cliente y conectarse al servidor
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 12345))

    # Recibir los valores de g y p desde el servidor
    g_p_data = client_socket.recv(1024).decode()
    g, p = map(int, g_p_data.split(","))
    
    print(f"Cliente: Parámetros recibidos g={g}, p={p}")
    # Generar el par de claves Diffie-Hellman
    private_key, public_key = diffie_hellman_generate_keypair(p, g)

    # Enviar la clave pública al servidor
    client_socket.send(str(public_key).encode())


    # Recibir la clave pública del servidor
    public_key_server = int(client_socket.recv(1024).decode())
    print(f"Cliente: Clave pública del servidor recibida: {public_key_server}")


    # Calcular el secreto compartido
    shared_secret = diffie_hellman_shared_secret(private_key, public_key_server, p)
    print(f"Cliente: Secreto compartido calculado: {shared_secret}")

    # Derivar la llave simétrica
    key = derive_key(shared_secret)
    print(f"Cliente: Llave simétrica derivada: {key.hex()}")

    # Ciclo para enviar el mismo mensaje 100 veces
    message = "Este es el mensaje repetido".encode()
    for i in range(100):
        # Cifrar el mensaje
        cipher = Salsa20.new(key=key)
        ciphertext = cipher.nonce + cipher.encrypt(message)

        # Enviar el mensaje cifrado al servidor
        client_socket.send(ciphertext)
        print(f"Cliente: ({i + 1}/100) Mensaje enviado al servidor")

        # Agregar un delay de 2 segundos entre cada envío
        time.sleep(2)

    # Cerrar la conexión
    client_socket.close()

if __name__ == "__main__":
    client()
