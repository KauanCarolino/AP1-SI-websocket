import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

users = {
    "madson": "123456"
}

user = input("Digite o usuario: ").lower().strip()

if user in users and users[user] == input("Digite a senha: ").strip():
  print("Acesso autorizado")
  msn = input("Digite sua mensagem: ")
  hash_object = hashlib.sha256()
  hash_object.update(msn.encode('utf-8'))
  print(type(hash_object))
else:
  print("Acesso negado")

#Tirando o Hash
hash_hex = hash_object.hexdigest()
hash_armazenado = hash_hex
print(hash_hex)

#Criando a criptografia
key = os.urandom(32)
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
padder = padding.PKCS7(128).padder()
msn_bytes = msn.encode()
msn_padder = padder.update(msn_bytes)+padder.finalize()
encryptor = cipher.encryptor()
ciphertext = encryptor.update(msn_padder)+encryptor.finalize()
print(ciphertext)

decryptor = cipher.decryptor()
decry_padder = decryptor.update(ciphertext)+decryptor.finalize()
unpadder = padding.PKCS7(128).unpadder()
plaintext = unpadder.update(decry_padder)+unpadder.finalize()

hash_object = hashlib.sha256(plaintext)
hash_atual = hash_object.hexdigest()

if hash_atual == hash_armazenado:
    print("Mensagem recebida com sucesso!")
    decode = plaintext.decode('utf-8')
    print(decode)
else:
    print("Mensagem comprometida")