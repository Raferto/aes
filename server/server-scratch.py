import sys
import socket
import os
import time
from aes import AES

key = "key123"
input_path = "./crypted-scratch.bin"

def received():
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
        f = open("./crypted-scratch.bin", "wb")
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

class Counter:
    def __init__(self) -> None:
        self.counter = 65536
    
    def next(self):
        self.counter+=3
    
    def to_list(self):
        return [int(x) for x in bin(self.counter)[2:18]]
    
def xor(list1, list2):
    return list(a^b for a,b in zip(list1,list2))

def ctr():
    file = open(input_path, 'rb')
    data = file.read()

    time_before = time.time()

    counter = Counter()

    aes = AES(key)
    decrypted_data = []
    temp = []
    for byte in data:
        temp.append(byte)
        if len(temp) == 16:
            decrypted_part = aes.encrypt(counter.to_list())
            counter.next()
            decrypted_data.extend( xor(decrypted_part, temp))
            temp.clear()

    if 0 < len(temp) < 16:
        empty_spaces = 16 - len(temp)
        for i in range(empty_spaces - 1):
            temp.append(0)
        temp.append(1)
        decrypted_part = aes.encrypt(counter.to_list())
        counter.next()
        decrypted_data.extend( xor(decrypted_part, temp))

    out_path = "./decrypted-scratch.png"
    with open(out_path, 'xb') as ff:
        ff.write(bytes(decrypted_data))

    time_after = time.time()
    print('New file here:--', time_after - time_before, ' seconds\n')

def non_ctr():
    file = open(input_path, 'rb')
    data = file.read()

    time_before = time.time()

    aes = AES(key)
    decrypted_data = []
    temp = []
    for byte in data:
        temp.append(byte)
        if len(temp) == 16:
            decrypted_part = aes.decrypt(temp)
            decrypted_data.extend(decrypted_part)
            del temp[:] 
    if 0 < len(temp) < 16:
                empty_spaces = 16 - len(temp)
                for i in range(empty_spaces - 1):
                    temp.append(0)
                temp.append(1)
                decrypted_part = aes.decrypt(temp)
                decrypted_data.extend(decrypted_part) 

    out_path = "./decrypted-scratch.png"
    with open(out_path, 'xb') as ff:
        ff.write(bytes(decrypted_data))

    time_after = time.time()
    print('New file here:--', time_after - time_before, ' seconds\n')

if __name__ == '__main__':
    received()
    ctr()