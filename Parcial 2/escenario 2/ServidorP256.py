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

def server():
    # Crear el servidor
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 12345))
    server_socket.listen(1)
    print("Servidor: Esperando conexión del cliente...")
    
    client_socket, addr = server_socket.accept()
    print(f"Servidor: Conectado a {addr}")

    # Inicializar contadores de bytes
    total_bytes_sent = 0
    total_bytes_received = 0

    # Generar el par de claves Diffie-Hellman (curva P-256)
    private_key, public_key = generate_keypair()

    # Enviar la clave pública al cliente
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    client_socket.send(public_bytes)
    total_bytes_sent += len(public_bytes)
    print("Servidor: Clave pública enviada al cliente.")

    # Recibir la clave pública del cliente
    client_public_bytes = client_socket.recv(1024)
    total_bytes_received += len(client_public_bytes)
    client_public_key = serialization.load_pem_public_key(client_public_bytes, backend=default_backend())
    print("Servidor: Clave pública del cliente recibida.")

    # Calcular el secreto compartido
    shared_secret = private_key.exchange(ec.ECDH(), client_public_key)
    shared_key = derive_shared_key(shared_secret)
    print(f"Servidor: Llave simétrica derivada: {shared_key.hex()}")

    # Ciclo de recepción y descifrado de mensajes
    for i in range(50):
        ciphertext = client_socket.recv(1024)
        total_bytes_received += len(ciphertext)
        plaintext = decrypt_message(shared_key, ciphertext)
        print(f"Servidor: Mensaje descifrado ({i + 1}): {plaintext.decode()}")

        # Enviar una respuesta cifrada
        response = f"Mensaje {i + 1} recibido correctamente.".encode()
        encrypted_response = encrypt_message(shared_key, response)
        client_socket.send(encrypted_response)
        total_bytes_sent += len(encrypted_response)

    client_socket.close()
    server_socket.close()

    # Mostrar estadísticas de transmisión
    print(f"Total de bytes enviados: {total_bytes_sent}")
    print(f"Total de bytes recibidos: {total_bytes_received}")

if __name__ == "__main__":
    server()
