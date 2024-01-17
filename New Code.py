from Crypto.PublicKey import DSA, ElGamal
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Util.number import getRandomRange
import os
import base64

# Function definitions

def generate_elgamal_keys(key_size):
    return ElGamal.generate(key_size, None)

def generate_dsa_keys(key_size):
    return DSA.generate(key_size)

def sign_data(dsa_key, data):
    hash_obj = SHA256.new(data)
    return DSS.new(dsa_key, 'fips-186-3').sign(hash_obj)

def verify_signature(dsa_key, data, signature):
    hash_obj = SHA256.new(data)
    verifier = DSS.new(dsa_key, 'fips-186-3')
    try:
        verifier.verify(hash_obj, signature)
        return True
    except ValueError:
        return False

def elgamal_key_to_dict(key):
    key_dict = {
        'p': int(key.p),
        'g': int(key.g),
        'y': int(key.y)
    }
    if hasattr(key, 'x'):
        key_dict['x'] = int(key.x)
    return key_dict

def save_data_to_python_file(file_path, variable_name, data):
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, 'w') as file:
        file.write(f"{variable_name} = {data}\n")

def encrypt_elgamal_chunked(public_key, plaintext, chunk_size):
    def encrypt_chunk(chunk):
        k = getRandomRange(1, int(public_key.p) - 1)
        chunk_int = int.from_bytes(chunk, 'big')
        c1 = pow(public_key.g, k, public_key.p)
        c2 = (pow(public_key.y, k, public_key.p) * chunk_int) % public_key.p
        return (c1, c2)

    chunks = [plaintext[i:i + chunk_size] for i in range(0, len(plaintext), chunk_size)]
    encrypted_chunks = [encrypt_chunk(chunk) for chunk in chunks]
    return encrypted_chunks

def tuples_list_to_bytes(tuples_list):
    return b' '.join([b','.join([str(x).encode() for x in t]) for t in tuples_list])

def bytes_to_tuples_list(bytes_data):
    tuples_list = []
    for item in bytes_data.split(b' '):
        c1, c2 = item.split(b',')
        tuples_list.append((int(c1), int(c2)))
    return tuples_list

def decrypt_elgamal_chunked(private_key, ciphertext_chunks):
    def decrypt_chunk(c1, c2):
        s = pow(c1, int(private_key.x), int(private_key.p))
        plaintext_int = (c2 * pow(s, int(private_key.p) - 2, int(private_key.p))) % int(private_key.p)
        return plaintext_int.to_bytes((plaintext_int.bit_length() + 7) // 8, 'big')

    decrypted_chunks = [decrypt_chunk(*chunk) for chunk in ciphertext_chunks]
    return b''.join(decrypted_chunks)

# Generate and save keys
key_size = 512  # Key size was reduced for performance
amaka_elgamal_key = generate_elgamal_keys(key_size)
ekene_elgamal_key = generate_elgamal_keys(key_size)
amaka_dsa_key = generate_dsa_keys(1024)  # DSA key size
ekene_dsa_key = generate_dsa_keys(1024)  # DSA key size

key_directory = "C:\\Users\\chequ\\Desktop\\CodingBox"
save_data_to_python_file(os.path.join(key_directory, 'KeyPairs.py'), 'key_data', {
    'amaka_elgamal': elgamal_key_to_dict(amaka_elgamal_key),
    'ekene_elgamal': elgamal_key_to_dict(ekene_elgamal_key),
    'amaka_dsa_public': amaka_dsa_key.publickey().export_key().decode(),
    'amaka_dsa_private': amaka_dsa_key.export_key().decode(),
    'ekene_dsa_public': ekene_dsa_key.publickey().export_key().decode(),
    'ekene_dsa_private': ekene_dsa_key.export_key().decode()
})

# Attempt to load key data
try:
    with open(os.path.join(key_directory, 'KeyPairs.py'), 'r') as file:
        exec(file.read())
    key_data = key_data  # Just to check if key_data is defined
except Exception as e:
    print(f"Error loading key data: {e}")
    exit(1)  # Exit if key data cannot be loaded

# Amaka encrypts and signs the file with Ekene's public key
notebook_path = os.path.join(key_directory, "NoteBook.txt")
with open(notebook_path, 'rb') as file:
    plaintext_bytes = file.read()

signature = sign_data(amaka_dsa_key, plaintext_bytes)
signature_path = os.path.join(key_directory, "DocumentSignature.sig")
with open(signature_path, 'wb') as file:
    file.write(signature)

print("Document signed by Amaka.")

chunk_size = 128  # Suitable chunk size
ekene_public_key = ElGamal.construct((key_data['ekene_elgamal']['p'], key_data['ekene_elgamal']['g'], key_data['ekene_elgamal']['y']))
ciphertext_chunks = encrypt_elgamal_chunked(ekene_public_key, plaintext_bytes, chunk_size)
encrypted_data_bytes = tuples_list_to_bytes(ciphertext_chunks)

# Save the encrypted document
encrypted_file_path = os.path.join(key_directory, "EncryptedNoteBook.txt")
with open(encrypted_file_path, 'wb') as file:
    file.write(base64.b64encode(encrypted_data_bytes))

print("Document encrypted and saved as 'EncryptedNoteBook.txt'.")

# Ekene decrypts the file using his private key
ekene_private_key = ElGamal.construct((key_data['ekene_elgamal']['p'], key_data['ekene_elgamal']['g'], key_data['ekene_elgamal']['y'], key_data['ekene_elgamal']['x']))
with open(encrypted_file_path, 'rb') as file:
    encrypted_data = file.read()
encrypted_data_bytes = base64.b64decode(encrypted_data)
ciphertext_chunks = bytes_to_tuples_list(encrypted_data_bytes)
decrypted_data = decrypt_elgamal_chunked(ekene_private_key, ciphertext_chunks)

# Save the decrypted document
decrypted_file_path = os.path.join(key_directory, "DecryptedNoteBook.txt")
with open(decrypted_file_path, 'wb') as file:
    file.write(decrypted_data)

print("Document decrypted and saved as 'DecryptedNoteBook.txt'.")

# Verify Amaka's signature
with open(signature_path, 'rb') as file:
    signature = file.read()

amaka_public_dsa_key = DSA.import_key(key_data['amaka_dsa_public'])
if verify_signature(amaka_public_dsa_key, plaintext_bytes, signature):
    print("Signature verification: SUCCESS. The document is authentic.")
else:
    print("Signature verification: FAILED. The document's authenticity cannot be verified.")




