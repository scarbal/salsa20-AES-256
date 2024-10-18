import socket
import os
import time
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
    iv = os.urandom(16)  # Generar IV aleatorio de 16 bytes
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    # Padding: AES requiere bloques de 16 bytes, añadimos padding si es necesario
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
    # Remover padding
    pad_len = plaintext_padded[-1]
    plaintext = plaintext_padded[:-pad_len]
    return plaintext

def client():
    # Crear el cliente y conectarse al servidor
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 12345))

    # Generar el par de claves Diffie-Hellman (curva P-256)
    private_key, public_key = generate_keypair()

    # Recibir la clave pública del servidor
    server_public_bytes = client_socket.recv(1024)
    server_public_key = serialization.load_pem_public_key(server_public_bytes, backend=default_backend())
    print("Cliente: Clave pública del servidor recibida.")

    # Enviar la clave pública al servidor
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    client_socket.send(public_bytes)
    print("Cliente: Clave pública enviada al servidor.")

    # Calcular el secreto compartido
    shared_secret = private_key.exchange(ec.ECDH(), server_public_key)
    shared_key = derive_shared_key(shared_secret)
    print(f"Cliente: Llave simétrica derivada: {shared_key.hex()}")

    # Ciclo para enviar mensajes cifrados
    for i in range(50):
        message = f"Mensaje secreto {i + 1}".encode()
        ciphertext = encrypt_message(shared_key, message)
        client_socket.send(ciphertext)

        # Recibir la respuesta cifrada del servidor
        encrypted_response = client_socket.recv(1024)
        response = decrypt_message(shared_key, encrypted_response)
        print(f"Cliente: Respuesta del servidor descifrada ({i + 1}): {response.decode()}")
        time.sleep(2)

    client_socket.close()

if __name__ == "__main__":
    client()
