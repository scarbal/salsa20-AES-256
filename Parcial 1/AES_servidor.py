import socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

# Crear el servidor
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('0.0.0.0', 12346))
server_socket.listen(1)

print("Esperando conexión del cliente...")
client_socket, addr = server_socket.accept()
print(f"Conectado a {addr}")

# Leer la llave AES de un archivo
with open('aes_keyfile.bin', 'rb') as key_file:
    key = key_file.read(32)

print(f"Servidor: Llave leída del archivo {key.hex()}")

# Cifrar un mensaje usando AES-256-CBC
message = b"Mensaje secreto AES-256 desde el servidor"
cipher = AES.new(key, AES.MODE_CBC)
ciphertext = cipher.iv + cipher.encrypt(pad(message, AES.block_size))

# Enviar mensaje cifrado al cliente
client_socket.send(ciphertext)
print(f"Servidor: Mensaje cifrado enviado {ciphertext.hex()}")

client_socket.close()
server_socket.close()
