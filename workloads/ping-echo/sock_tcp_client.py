#!/usr/bin/env python3

import os
import sys
import socket
import time
import signal
import random
from datetime import datetime, timezone

import argparse

parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)

parser.add_argument('-s', '--server', type=str, default='localhost', help='server address to connect to')
parser.add_argument('-p', '--port', type=int, default=8080, help='port number to connect to on the server')
parser.add_argument('-x', '--run-count', type=int, default=1, help='number of times to run the test')
parser.add_argument('-n', '--requests', type=int, default=5, help='number of requests to send per run')
parser.add_argument('-l', '--log-dir', type=str, default='/tmp/ping', help='Directory path to output the log file')

args = parser.parse_args()

os.makedirs(args.log_dir, exist_ok=True)
timestamp = datetime.now(timezone.utc).isoformat()
filename = f"ping_{timestamp}.csv"
log_path = os.path.join(args.log_dir, filename)

should_exit = 0
def signal_handler(signum, frame):
  if signum != signal.SIGINT:
    return
  global should_exit
  global sock
  should_exit += 1
  signame = signal.Signals(signum).name

  if should_exit >= 2:
    try:
      sock.close()
    except NameError:
      pass
    sys.exit()

signal.signal(signal.SIGINT, signal_handler)

with open(log_path, 'w') as f:
  log = 'run,start,end\n'
  print(log, end='')
  f.write(log)

  for run_iteration in range(args.run_count):
    if should_exit > 0:
      break

    time.sleep(2)
    global sock
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((args.server, args.port))

    for records in range(args.requests):
      if should_exit > 0:
        break

      start = time.time_ns()
      try:
        data = f'ping-{start}'.encode()
        sock.sendall(data)
        data_recv = sock.recv(1024)
        if not data_recv: break
      except Exception as e:
        print(e)
        break
      end = time.time_ns()

      log = f'{run_iteration},{start},{end}\n'
      print(log, end='')
      f.write(log)

    sock.close()
