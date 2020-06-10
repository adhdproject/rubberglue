from __future__ import print_function

import socket,asyncore
import time
import random
import hashlib
import os
import six

LOGGING_FILE = 'log.txt'
WHITELIST = ['127.0.0.1','localhost']
LOCAL_IP = ''
MAXCONNECTIONS = 100
MAX_LEN = 4096

def parse_input_string_to_hash(s):
	"""This function handles inputs to the hashing function for py2 and 3."""
	if six.PY2:
		return str(s)
	return s.encode()

class Core(object):
	def __init__(self, logfile, syslog=False, cap=False):
		self.logfile = logfile
		self.cap = cap
		fi = open(self.logfile, 'a')
		fi.close()
		if not os.path.exists('./capture'):
			os.makedirs('./capture')
		
	def logg(self, msg):
		fi = open(self.logfile, 'a')
		fi.write('{time}; {msg} \n'.format(msg=msg, time=time.strftime('%H:%M:%S %m/%d/%Y')))
		fi.close()
	
	def make_hash(self, data):
		return hashlib.sha1(parse_input_string_to_hash(data)).hexdigest()

	def capture(self, tag, data):
		if not self.cap == False:
			fi = open(r'capture/{tag}'.format(tag=str(tag)), 'a')
			fi.write(str(data))
			fi.close()

class Forwarder(asyncore.dispatcher, object):
	def __init__(self, ip, port, backlog=5):
		asyncore.dispatcher.__init__(self)
		self.remoteport=port
		self.port = port
		self.create_socket(socket.AF_INET,socket.SOCK_STREAM)
		self.set_reuse_addr()
		self.bind((ip,port))
		self.listen(backlog)

	def handle_accept(self):
		if len(asyncore.socket_map) > MAXCONNECTIONS:
			return
		conn, addr = self.accept()
		tag = instance.make_hash('{time}---!!!---{addr}---!!!---{port}'.format(time=time.strftime('%H:%M:%S %m/%d/%Y'), addr=str(addr), port=str(self.port)))
		print('Connection from: {addr}:{addw}->{port}'.format(addr=addr[0], addw=str(addr[1]), port=str(self.port)))
		instance.logg('Connection from: {addr}:{addw}->{port}; {tag}'.format(addr=addr[0], addw=str(addr[1]), port=str(self.port), tag=tag))
		if addr[0] not in WHITELIST:
			Sender(Receiver(conn, tag),addr[0],self.remoteport, tag)
		else:
			return
class Receiver(asyncore.dispatcher, object):
	def __init__(self,conn, tag):
		self.tag = tag
		asyncore.dispatcher.__init__(self,conn)
		self.from_remote_buffer=''
		self.to_remote_buffer=''
		self.Sender=None

	def handle_connect(self):
		pass

	def handle_read(self):
		read = self.recv(MAX_LEN)
		self.from_remote_buffer += str(read)
		if not read == None:
			instance.capture(self.tag, read)

	def writable(self):
		return (len(self.to_remote_buffer) > 0)

	def handle_write(self):
		sent = self.send(self.to_remote_buffer)
		self.to_remote_buffer = self.to_remote_buffer[sent:]

	def handle_close(self):
		self.close()
		if self.Sender:
			self.Sender.close()

class Sender(asyncore.dispatcher, object):
	def __init__(self, Receiver, remoteaddr, remoteport, tag):
		asyncore.dispatcher.__init__(self)
		self.Receiver=Receiver
		self.tag = tag
		Receiver.Sender=self
		self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			self.connect((remoteaddr, remoteport))
		except socket.error:
			print('We are unable to forward to the remote machine on port {port}'.format(port=remoteport))
		self.remoteaddr = remoteaddr
		self.remoteport = remoteport

	def handle_error(self):
		print('We are unable to forward to the remote machine at {addr}:{port} (probably, their port is closed)'.format(addr=self.remoteaddr, port=self.remoteport))
		self.close()

	def handle_connect(self):
		pass

	def handle_read(self):
		read = self.recv(MAX_LEN)
		self.Receiver.to_remote_buffer += read
		if not read == None:
			instance.capture(self.tag, str(read))

	def writable(self):
		return (len(self.Receiver.from_remote_buffer) > 0)

	def handle_write(self):
		sent = self.send(self.Receiver.from_remote_buffer)
		self.Receiver.from_remote_buffer = self.Receiver.from_remote_buffer[sent:]

	def handle_close(self):
		self.close()
		self.Receiver.close()


# Execute the main flow of the script here
if __name__ == '__main__':
	import sys

	if len(sys.argv) < 2:
		print('You need to give a port')
		print('Usage: {s} <port>'.format(s=sys.argv[0]))
		sys.exit(1)

	instance = Core(LOGGING_FILE)
	
	# Initiate a listener on all supplied ports
	for port in sys.argv[1:]:
		try:
			int(port)
		except ValueError:
			print('Please supply only integer values as ports')
			sys.exit(-1)
		if int(port) < 1 or int(port) > 65535:
			print('Please supply only ports in the range 0 < port < 65536')
			sys.exit(-2)
		
		Forwarder(LOCAL_IP,int(port))
	asyncore.loop()
