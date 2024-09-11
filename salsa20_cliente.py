import socket
from Crypto.Cipher import Salsa20

# Crear el cliente
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('192.168.1.61', 12345)) #ingresar ipv4 del servidor

# Recibir la llave del servidor
key = client_socket.recv(32)
print(f"Cliente: Llave recibida {key.hex()}")

# Recibir mensaje cifrado
ciphertext = client_socket.recv(1024)
nonce = ciphertext[:8]  # Salsa20 usa una nonce de 8 bytes
ciphertext = ciphertext[8:]

# Descifrar el mensaje
cipher = Salsa20.new(key=key, nonce=nonce)
plaintext = cipher.decrypt(ciphertext)
print(f"Cliente: Mensaje descifrado '{plaintext.decode()}'")

client_socket.close()
