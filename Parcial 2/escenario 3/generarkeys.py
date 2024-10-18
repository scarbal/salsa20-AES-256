import pickle
from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes

def generate_elgamal_keypair():
    # Generar la clave ElGamal
    key = ElGamal.generate(2048, get_random_bytes)
    return key, key.publickey()

def save_keys(private_key, public_key):
    # Guardar la clave privada en un archivo
    with open('private_key.pkl', 'wb') as f:
        pickle.dump(private_key, f)
    # Guardar la clave pública en un archivo
    with open('public_key.pkl', 'wb') as f:
        pickle.dump(public_key, f)

if __name__ == "__main__":
    private_key, public_key = generate_elgamal_keypair()
    save_keys(private_key, public_key)
    print("Claves ElGamal generadas y guardadas.")
