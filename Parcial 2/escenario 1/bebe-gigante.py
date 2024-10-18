import math
import time
import hashlib
from Crypto.Cipher import Salsa20

# Función para calcular (base^exp) % mod de manera eficiente
def modular_exponentiation(base, exp, mod):
    result = 1
    base = base % mod
    while exp > 0:
        if (exp % 2) == 1:
            result = (result * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    return result

# Algoritmo "Pasos de Bebé, Pasos de Gigante" para resolver el logaritmo discreto con límite de iteraciones
def baby_step_giant_step(g, y, p, max_iterations=1000000):
    m = math.isqrt(p) + 1  # Calcular m = sqrt(p)

    # Paso de bebé: precomputar g^j mod p para j = 0, 1, ..., m-1
    baby_steps = {}
    for j in range(m):
        baby_step_value = modular_exponentiation(g, j, p)
        baby_steps[baby_step_value] = j

    # Inversa modular de g^m mod p
    g_m_inv = modular_exponentiation(g, m * (p - 2), p)  # g^(-m) = g^(p-1-m)

    # Paso de gigante: calcular y * g^(-im) mod p y buscar coincidencias
    current_value = y
    for i in range(m):
        if i >= max_iterations:  # Si superamos el límite de iteraciones, detener
            print("Atacante: Límite de iteraciones alcanzado.")
            return None

        if current_value in baby_steps:
            # Solución encontrada: x = im + j
            return i * m + baby_steps[current_value]

        current_value = (current_value * g_m_inv) % p

    return None  # Si no se encuentra la solución

# Función para derivar la llave simétrica usando SHA-256
def derive_key(shared_secret):
    shared_secret_bytes = str(shared_secret).encode()
    key = hashlib.sha256(shared_secret_bytes).digest()
    return key

# Función para descifrar el mensaje usando Salsa20
def decrypt_message(key, encrypted_message):
    # Extraer el nonce (primeros 8 bytes) y el texto cifrado (resto)
    nonce = encrypted_message[:8]
    ciphertext = encrypted_message[8:]
    
    # Descifrar el mensaje
    cipher = Salsa20.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

# Ejemplo del atacante que intercepta y descifra mensajes
if __name__ == "__main__":
    # Parámetros públicos (parte del problema del logaritmo discreto)
    p = 137264501074495181280555132673901931323332164724815133317526595627537522562067022989603699054588480389773079016561323343477054349336451609284971148159280724829128531552270321268457769520042856144429883077983691811201653430137376919960068969990507421437958462547891425943025305810160065324145921753228735283903  # Un número primo (público)
    g = 40746562294764965373407784234554073062674073565341303353016758609344799210654104763969824808430330931109448281620048720300276969942539907157417365502013807736680793541720602226570436490901677489617911977499169334249484471027700239163555304280499401445437347279647322836086848012965178946904650279473615383579   # Generador (público)
    y = 132489296488646844475000687746453171626793975515816017986439384762707631808016762650501822547456308768044750107058878614720140923905297587962508932485480879345895289927310572313125879217465110687773144063879345798598457534057219901640493549873700972494962160567494022174981602091899921537902438439990371047633  # Clave pública del servidor g^x mod p (interceptada)

    # Tiempo inicial
    start_time = time.time()

    # Intentar encontrar el valor de x (clave privada del servidor) usando "Pasos de bebé y pasos de gigante"
    print("Atacante: Intentando encontrar la clave privada usando 'Pasos de Bebé y Pasos de Gigante'...")
    x = baby_step_giant_step(g, y, p)

    if x is not None:
        print(f"Atacante: ¡Clave privada encontrada! x = {x}")
        # llave cliente
        public_key_client = 17248756892471048435051512215866320733767617843136387030945349172099213065590867303351805375494139313923252568618672826083802633003681907100122145202037929004525642551187515754407287668986742855811945293227515162307579519724651297519962423066831914730103298392394417163172452615482852153314970244037632252942 

        # Calcular el secreto compartido usando x y la clave pública del cliente
        shared_secret = modular_exponentiation(public_key_client, x, p)
        print(f"Atacante: Secreto compartido calculado: {shared_secret}")

        # Derivar la llave simétrica a partir del secreto compartido
        key = derive_key(shared_secret)
        print(f"Atacante: Llave simétrica derivada: {key.hex()}")

        # Ingresa el mensaje cifrado interceptado en formato hexadecimal
        encrypted_message_hex = '84a0e45f82897acd3fcd7c5e2fbd967286ad470768b856b2afaa2b100f43172e0b4e55'
        
        # Convertir el mensaje cifrado de hexadecimal a bytes
        encrypted_message = bytes.fromhex(encrypted_message_hex)
        
        # Descifrar el mensaje usando la llave derivada y el nonce extraído del mensaje
        plaintext = decrypt_message(key, encrypted_message)
        print(f"Atacante: Mensaje descifrado: {plaintext.decode()}")

    else:
        print("Atacante: No se encontró la clave privada en el tiempo dado.")

    # Calcular el tiempo transcurrido
    elapsed_time = time.time() - start_time

    # Si el tiempo transcurrido es menor a 5 segundos, realizar pausa
    if elapsed_time < 3600:
        time.sleep(5 - elapsed_time)  # Pausa el tiempo restante para llegar a 5 segundos

    # Calcular el tiempo total final
    total_elapsed_time = time.time() - start_time
    elapsed_minutes = total_elapsed_time / 60  # Convertir a minutos

    # Imprimir el tiempo total en segundos y minutos
    print(f"Tiempo total de ejecución: {total_elapsed_time:.2f} segundos / {elapsed_minutes:.2f} minutos")
