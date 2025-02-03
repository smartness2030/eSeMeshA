#!/usr/bin/env python3

import sys
import socket
import signal
import asyncio

import argparse

parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)

parser.add_argument('host', type=str, nargs='?', default='localhost', help='the host/IP address to bind the server to')
parser.add_argument('port', type=int, nargs='?', default=8080, help='the port number to bind the server to')

args = parser.parse_args()

connections = set()

async def handle_client(conn, addr):
  print(f'accepted {addr}')
  connections.add(conn)

  loop = asyncio.get_event_loop()

  while True:
    data_recv = await loop.sock_recv(conn, 1024)
    if not data_recv: break
    #print(f'got {data_recv} from {addr}')
    await loop.sock_sendall(conn, data_recv)# + b'[reply;python]')

  conn.close()
  connections.remove(conn)
  print(f'closed {addr}')

async def server_loop():
  # socket.SOCK_DGRAM
  global sock
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM | socket.SOCK_NONBLOCK)
  sock.bind((args.host, args.port))
  sock.listen(1024)

  loop = asyncio.get_event_loop()

  print(f'listening on {(args.host, args.port)}')
  while True:
    conn, addr = await loop.sock_accept(sock)
    loop.create_task(handle_client(conn, addr))

should_exit = 0
def signal_handler(signum, frame):
  if signum != signal.SIGINT:
    return
  global should_exit
  global sock
  should_exit += 1

  try:
    sock.close()
  except NameError:
    pass

  if should_exit >= 2:
    for conn in connections:
      print('closing conn')
      conn.close()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

asyncio.run(server_loop())
