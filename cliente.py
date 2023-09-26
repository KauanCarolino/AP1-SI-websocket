import websockets
import asyncio
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

async def menssage():
    tentativas_max = 3
    tentativa_atual = 0
    users = {
        "santiago": "063688",
        "kauan": "987654"
    }
    async with websockets.connect("ws://192.168.3.13:7000") as socket:
        while (tentativa_atual < tentativas_max):
            user = input("Digite o usuário: ").lower().strip()

            if user in users and users[user] == input("Digite a senha: ").strip():
                print("Acesso autorizado")
                msn = input("digite uma mensagem pro Servidor: ")
                hash_object = hashlib.sha256()
                hash_object.update(msn.encode('utf-8'))
                access = True

                # Tirando o Hash
                hash_object = hashlib.sha256()
                hash_object.update(msn.encode('utf-8'))
                hash_hex = hash_object.hexdigest()
                hash_armazenado = hash_hex

                # preparando a criptografia
                key = os.urandom(32)
                iv = os.urandom(16)
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
                msn_bytes = msn.encode('utf-8')
                padder = padding.PKCS7(128).padder()
                msn_bytes_padded = padder.update(msn_bytes) + padder.finalize()
                encryptor = cipher.encryptor()
                ciphertext = encryptor.update(msn_bytes_padded) + encryptor.finalize()
                print(ciphertext)

                await socket.send(key)
                await socket.send(iv)
                await socket.send(hash_armazenado)
                await socket.send(ciphertext)
                print(await socket.recv())
                break
            else:
                tentativa_atual += 1
                restante = tentativas_max - tentativa_atual

                if restante > 0:
                    print("usuario ou senha incorreta, tentativas restantes ", restante)
                else:
                    print("Numero de tentativas excedidas. Acesso bloqueado!")
                    break
while True:
    asyncio.get_event_loop().run_until_complete(menssage())