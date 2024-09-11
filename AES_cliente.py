import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Crear el cliente
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('192.168.1.61', 12346))

# Leer la llave AES de un archivo (simulando la recepción por un canal alterno)
with open('aes_keyfile.bin', 'rb') as key_file:
    key = key_file.read(32)

print(f"Cliente: Llave leída del archivo {key.hex()}")

# Recibir mensaje cifrado
ciphertext = client_socket.recv(1024)
iv = ciphertext[:16]  # El tamaño de IV en AES es de 16 bytes
ciphertext = ciphertext[16:]

# Descifrar el mensaje
cipher = AES.new(key, AES.MODE_CBC, iv=iv)
plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
print(f"Cliente: Mensaje descifrado '{plaintext.decode()}'")

client_socket.close()
