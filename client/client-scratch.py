import sys
import socket
import os
import time
from aes import AES

server_ip = ['127.0.0.1']
key = "key123"
input_path = "./file.png"

def send():
    for i in server_ip:
        # Create a TCP/IP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connect the socket to the port where the server is listening
        server_address = (i, 10000)
        print(f"connecting to {server_address}")
        sock.connect(server_address)

        try:
            # Send data
            img = "./crypted-scratch.bin"
            imgfile = open(img, 'rb')
            imgbytes = imgfile.read()
            print(f"sending {img}")
            sock.sendall(imgbytes)
        finally:
            print("closing")
            sock.close()

def non_ctr():
    file = open(input_path, 'rb')
    data = file.read()

    time_before = time.time()

    aes = AES(key)
    crypted_data = []
    temp = []

    for byte in data:
        temp.append(byte)
        if len(temp) == 16:
            crypted_part = aes.encrypt(temp)
            crypted_data.extend(crypted_part)
            temp.clear()
            
    if 0 < len(temp) < 16:
                empty_spaces = 16 - len(temp)
                for i in range(empty_spaces - 1):
                    temp.append(0)
                temp.append(1)
                crypted_part = aes.encrypt(temp)
                crypted_data.extend(crypted_part)

    out_path = "./crypted-scratch.bin"
    with open(out_path, 'xb') as ff:
        ff.write(bytes(crypted_data))

    time_after = time.time()
        
    print('New file here:--', time_after - time_before, ' seconds\n')

def ctr():
    file = open(input_path, 'rb')
    data = file.read()

    time_before = time.time()

    aes = AES(key)
    counter = Counter()
    crypted_data = []
    temp = []

    for byte in data:
        temp.append(byte)
        if len(temp) == 16:
            crypted_part = aes.encrypt(counter.to_list())
            counter.next()
            crypted_data.extend( xor(crypted_part, temp))
            temp.clear()
            
    if 0 < len(temp) < 16:
        empty_spaces = 16 - len(temp)
        for i in range(empty_spaces - 1):
            temp.append(0)
        temp.append(1)
        crypted_part = aes.encrypt(counter.to_list())
        counter.next()
        crypted_data.extend( xor(crypted_part, temp))

    out_path = "./crypted-scratch.bin"
    with open(out_path, 'xb') as ff:
        ff.write(bytes(crypted_data))

    time_after = time.time()
        
    print('New file here:--', time_after - time_before, ' seconds\n')

class Counter:
    def __init__(self) -> None:
        self.counter = 65536
    
    def next(self):
        self.counter+=3
    
    def to_list(self):
        return [int(x) for x in bin(self.counter)[2:18]]
    
def xor(list1, list2):
    return list(a^b for a,b in zip(list1,list2))

if __name__ == '__main__':
    ctr()
    send()