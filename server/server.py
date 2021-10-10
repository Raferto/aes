import sys
import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Bind the socket to the port
server_address = ('127.0.0.1', 10000)
print(f"starting up on {server_address}")
sock.bind(server_address)
# Listen for incoming connections
sock.listen(1)
while True:
    # Wait for a connection
    print("waiting for a connection")
    connection, client_address = sock.accept()
    print(f"connection from {client_address}")
    # Receive the data in small chunks and retransmit it
    f = open("encrypted_data.bin", "wb")
    while True:
        data = connection.recv(32)
        f.write(data)
      #   print(f"received {data}")
        if not data:
           break
    # Clean up the connection
    f.close()
    connection.close()
    break;

file_in = open("encrypted_data.bin", "rb")

private_key = RSA.import_key(open("../private.pem").read())

enc_session_key, nonce, ciphertext = \
   [ file_in.read(x) for x in (private_key.size_in_bytes(), 8, -1) ]

# Decrypt the session key with the private RSA key
cipher_rsa = PKCS1_OAEP.new(private_key)
session_key = cipher_rsa.decrypt(enc_session_key)

# Decrypt the data with the AES session key
cipher_aes = AES.new(session_key, AES.MODE_CTR, nonce=nonce)
data = cipher_aes.decrypt(ciphertext)
f = open("image.png", "wb")
f.write(data)
f.close()
