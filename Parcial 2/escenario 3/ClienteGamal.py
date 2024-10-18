import socket
import pickle
from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes

def elgamal_encrypt(public_key, message):
    # Cifrar el mensaje
    ciphertext = public_key.encrypt(message, 32)
    return ciphertext

def client():
    # Crear el cliente y conectarse al servidor
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 65433))

    # Recibir la clave pública del servidor
    public_key_bytes = client_socket.recv(4096)
    public_key = ElGamal.import_key(public_key_bytes)
    print("Cliente ElGamal: Clave pública recibida.")

    # Ciclo para enviar 50 mensajes
    for i in range(50):
        message = f"Este es el mensaje número {i + 1} secreto usando ElGamal.".encode()
        encrypted_message = elgamal_encrypt(public_key, message)
        print(f"Cliente ElGamal: Mensaje cifrado enviado: {encrypted_message}")

        # Enviar el mensaje cifrado al servidor
        client_socket.send(str(encrypted_message).encode('utf-8'))

    client_socket.close()

if __name__ == "__main__":
    client()
