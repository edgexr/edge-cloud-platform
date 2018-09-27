#!/usr/bin/python3

import socket
import random

port = 2014

ssocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ssocket.bind(('', port))
print('servert port', port)

while True:
    num = random.randint(0,10)
    data, client_addr = ssocket.recvfrom(port)
    new_data = data.upper()

    ssocket.sendto(new_data, client_addr)
#    print('recved', data)

