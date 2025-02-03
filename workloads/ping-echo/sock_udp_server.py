#!/usr/bin/env python3

import sys
import socket
import signal

assert len(sys.argv) == 2, 'wrong argument count. expected `python3 sock_server.py 127.0.0.1:8080`'

#[HOST, PORT] = '192.168.0.112:6300'.split(':')
[HOST, PORT] = sys.argv[1].split(':')
PORT = int(PORT)

def server_loop():
  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  sock.bind((HOST, PORT))

  def close_handler(signum, frame):
    sock.close()
    sys.exit(0)

  signal.signal(signal.SIGINT, close_handler)

  while True:
    data_recv, (client_addr, client_port) = sock.recvfrom(1024)
    print(f'got {data_recv} from {(client_addr, client_port)}')
    sock.sendto(data_recv + b'[reply;python]', (client_addr, client_port))

server_loop()
