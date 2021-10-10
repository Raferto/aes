import sys
import socket
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

img = "./file/lambang-its-png-v2.png"
imgfile = open(img, 'rb')
data = imgfile.read()
file_out = open("encrypted_data.bin", "wb")

recipient_key = RSA.import_key(open("../receiver.pem").read())
session_key = get_random_bytes(16)

# Encrypt the session key with the public RSA key
cipher_rsa = PKCS1_OAEP.new(recipient_key)
enc_session_key = cipher_rsa.encrypt(session_key)

# Encrypt the data with the AES session key
cipher_aes = AES.new(session_key, AES.MODE_CTR)
ciphertext = cipher_aes.encrypt(data)

print(len(cipher_aes.nonce))

[ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, ciphertext) ]
file_out.close()


server_ip = ['127.0.0.1']
count = 0

for i in server_ip:
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    server_address = (i, 10000)
    print(f"connecting to {server_address}")
    sock.connect(server_address)

    try:
        # Send data
        img = "encrypted_data.bin"
        imgfile = open(img, 'rb')
        imgbytes = imgfile.read()
        print(f"sending {img}")
        sock.sendall(imgbytes)
    finally:
        print("closing")
        sock.close()
