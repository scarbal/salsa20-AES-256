import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# Generar par de claves RSA
def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Descifrar mensaje con RSA OAEP
def rsa_decrypt(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def server():
    # Crear el servidor
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 65432))
    server_socket.listen(1)
    print("Servidor RSA: Esperando conexión...")

    conn, addr = server_socket.accept()
    print(f"Servidor RSA: Conectado con {addr}")

    # Generar las claves RSA
    private_key, public_key = generate_rsa_keypair()

    # Enviar clave pública al cliente
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_size = len(public_pem)  # Tamaño de la clave pública
    conn.send(public_pem)
    print(f"Servidor RSA: Clave pública enviada al cliente ({public_key_size} bytes).")

    # Inicializar contador de datos transmitidos
    total_data_transmitted = public_key_size

    # Ciclo de recepción y descifrado de 50 mensajes
    for i in range(50):
        # Recibir el mensaje cifrado del cliente
        encrypted_message = conn.recv(4096)
        if not encrypted_message:
            print("No se recibieron más mensajes. Cerrando conexión.")
            break  # Salir si no hay más datos

        encrypted_message_size = len(encrypted_message)  # Tamaño del mensaje cifrado
        total_data_transmitted += encrypted_message_size
        print(f"Servidor RSA: Mensaje cifrado recibido ({encrypted_message_size} bytes).")

        # Descifrar el mensaje
        decrypted_message = rsa_decrypt(private_key, encrypted_message)
        print(f"Servidor RSA: Mensaje descifrado ({i + 1}/50): {decrypted_message.decode()}")

    # Imprimir la cantidad total de información transmitida
    print(f"Cantidad total de información transmitida: {total_data_transmitted} bytes")

    conn.close()
    server_socket.close()

if __name__ == "__main__":
    server()
