import socket
from Crypto.Cipher import Salsa20
from Crypto.Random import get_random_bytes

# Crear el servidor
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))
server_socket.listen(1)

print("Esperando conexión del cliente...")
client_socket, addr = server_socket.accept()
print(f"Conectado a {addr}")

# Generar una llave de 256 bits
key = get_random_bytes(32)  # 256 bits
print(f"Servidor: Llave generada {key.hex()}")

# Enviar la llave al cliente
client_socket.send(key)

# Cifrar un mensaje usando Salsa20
message = b"Mensaje secreto desde el servidor"
cipher = Salsa20.new(key=key)
ciphertext = cipher.nonce + cipher.encrypt(message)  # La nonce se incluye con el texto cifrado

# Enviar mensaje cifrado al cliente
client_socket.send(ciphertext)
print(f"Servidor: Mensaje cifrado enviado {ciphertext.hex()}")

client_socket.close()
server_socket.close()
