import socket
import pickle
from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes

def load_keys():
    # Cargar la clave privada
    with open('private_key.pkl', 'rb') as f:
        private_key = pickle.load(f)
    # Cargar la clave pública
    with open('public_key.pkl', 'rb') as f:
        public_key = pickle.load(f)
    return private_key, public_key

def elgamal_decrypt(private_key, encrypted_message):
    return private_key.decrypt(encrypted_message)

def server():
    # Crear el servidor
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 65433))
    server_socket.listen(1)
    print("Servidor ElGamal: Esperando conexión...")

    conn, addr = server_socket.accept()
    print(f"Servidor ElGamal: Conectado con {addr}")

    # Cargar claves ElGamal
    private_key, public_key = load_keys()
    
    # Enviar la clave pública al cliente
    public_key_bytes = public_key.export_key(format='DER')
    conn.send(public_key_bytes)
    print("Servidor ElGamal: Clave pública enviada al cliente.")

    total_data_transmitted = len(public_key_bytes)  # Tamaño de la clave pública

    # Ciclo de recepción y descifrado de 50 mensajes
    for i in range(50):
        # Recibir mensaje cifrado del cliente
        encrypted_message_bytes = conn.recv(4096)
        if not encrypted_message_bytes:
            break
        # Convertir el mensaje recibido en una tupla
        encrypted_message = eval(encrypted_message_bytes.decode('utf-8'))  
        print(f"Servidor ElGamal: Mensaje cifrado recibido: {encrypted_message}")

        # Sumar el tamaño del mensaje cifrado a la cantidad total transmitida
        total_data_transmitted += len(encrypted_message_bytes)

        # Descifrar el mensaje
        decrypted_message = elgamal_decrypt(private_key, encrypted_message)
        print(f"Servidor ElGamal: Mensaje descifrado ({i + 1}): {decrypted_message.decode()}")

    # Imprimir la cantidad total de información transmitida
    print(f"Cantidad total de información transmitida: {total_data_transmitted} bytes")

    conn.close()
    server_socket.close()

if __name__ == "__main__":
    server()
