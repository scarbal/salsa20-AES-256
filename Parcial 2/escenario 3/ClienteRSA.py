import socket
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

# Cifrar mensaje con la clave pública del servidor
def rsa_encrypt(public_key, message):
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def client():
    # Crear el cliente y conectarse al servidor
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 65432))

    # Recibir la clave pública del servidor
    public_pem = client_socket.recv(4096)
    public_key = serialization.load_pem_public_key(public_pem)
    print("Cliente RSA: Clave pública recibida.")

    # Ciclo para enviar 50 mensajes
    for i in range(50):
        # Cifrar el mensaje
        message = f"Este es el mensaje número {i + 1} secreto usando RSA OAEP.".encode()
        encrypted_message = rsa_encrypt(public_key, message)
        print(f"Cliente RSA: Mensaje cifrado enviado: {encrypted_message.hex()}")

        # Enviar el mensaje cifrado al servidor
        client_socket.send(encrypted_message)

    client_socket.close()

if __name__ == "__main__":
    client()
