#!/usr/bin/python3

import socket
#import datatime
import time
import sys

#server_name = 'localhost'
server_name = '40.113.219.126'
port = 2015
data = 'ping'
data_to_send = data.encode('ascii')
data_size = sys.getsizeof(bytes(data, 'utf-8'))
#print(data_size)
number_of_pings = int(sys.argv[1])
server_name = sys.argv[2]
port = int(sys.argv[3])

client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_socket.settimeout(1)

# test the connection. sometimes the connection is slower on 1st connection.
# reopen the connection if so
for i in range(5):
    start_time_pre = time.time()
    client_socket.sendto(data_to_send,(server_name, port))
    client_socket.recvfrom(data_size)
    rtt_pre = ((time.time()) - start_time_pre) * 1000
    if rtt_pre > 54:
#        print('reopening socket')
        time.sleep(1)
        client_socket.close()
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client_socket.settimeout(1)
    else:
        break
 
for i in range(number_of_pings):
#    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#    client_socket.settimeout(1)

    start_time = time.time()
#    print('{} {}'.format(i,start_time))
    client_socket.sendto(data_to_send,(server_name, port))
#    start_time = time.time()
    try:
        new_data, addr = client_socket.recvfrom(data_size)
#        print(new_data)
        rtt = ((time.time()) - start_time)
        #print('latency {} {}'.format(rtt * 1000, rtt))
        
        sys.stdout.write('latency ' + str(rtt*1000) + ' ' + str(rtt) + '\n')
    except socket.timeout:
        print('error: request timed out')
    except Exception as e:
        print('error=', e)
    #client_socket.close()
    time.sleep(1)
client_socket.close()
