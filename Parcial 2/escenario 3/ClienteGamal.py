from Crypto.PublicKey import ElGamal
import json
import socket
import base64
import os
from Crypto.Random import random

# Crear socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 65433))
print("Conexión establecida con el servidor ElGamal.")

# Obtener la ruta del directorio actual
current_directory = os.path.dirname(os.path.abspath(__file__))
public_key_path = os.path.join(current_directory, "pk.json")

# Cargar la clave pública (se asume que el servidor generó las claves y las compartió)
with open(public_key_path, "r") as f:
    public_key_data = json.load(f)

# Reconstruir la clave pública de ElGamal
p = int(public_key_data['p'])
g = int(public_key_data['g'])
y = int(public_key_data['y'])

# Función para cifrar manualmente usando ElGamal
def elgamal_encrypt(message, p, g, y):
    m = int.from_bytes(message.encode(), 'big')
    k = random.StrongRandom().randint(1, p - 1)
    c1 = pow(g, k, p)
    c2 = (m * pow(y, k, p)) % p
    return (c1, c2)

# Mensaje estático que se enviará al servidor
static_message = "Este es un mensaje secreto usando ElGamal."

# Crear un ciclo de comunicación para enviar el mensaje estático 10 veces
for i in range(1):
    # Cifrar el mensaje
    c1, c2 = elgamal_encrypt(static_message, p, g, y)

    # Convertir los valores cifrados a Base64 y enviar al servidor
    cipher_text_b64_c1 = base64.b64encode(str(c1).encode()).decode()
    cipher_text_b64_c2 = base64.b64encode(str(c2).encode()).decode()

    # Enviar al servidor
    client_socket.sendall(cipher_text_b64_c1.encode())
    client_socket.sendall(cipher_text_b64_c2.encode())

    print(f"Cliente: Mensaje cifrado enviado ({i + 1}/10).")

# Finalizar la conexión
client_socket.sendall(b'exit')  # Enviar señal de cierre
client_socket.close()
print("Conexión cerrada con el servidor.")
