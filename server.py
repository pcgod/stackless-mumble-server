#!/usr/local/bin/spython -OO

#print_function
from __future__ import unicode_literals

import binascii
import sys
import struct
import stackless
#import stacklesssocket
import socket
import socketlibevent
import random
import platform
import weakref

from cryptstate import CryptState
import Mumble_pb2 as MumbleProto
import pds

sys.modules[b'socket'] = socketlibevent

Permissions = {
	b'None': 0x0,
	b'Write': 0x1,
	b'Traverse': 0x2,
	b'Enter': 0x4,
	b'Speak': 0x8,
	b'MuteDeafen': 0x10,
	b'Move': 0x20,
	b'MakeChannel': 0x40,
	b'LinkChannel': 0x80,
	b'Whisper': 0x100,
	b'TextMessage': 0x200,
	b'MakeTempChannel': 0x400,

	# Root channel only
	b'Kick': 0x10000,
	b'Ban': 0x20000,
	b'Register': 0x40000,
	b'SelfRegister': 0x80000,

	b'Cached': 0x8000000,
	b'All': 0xf07ff
}

UDPMessageTypes = [
	b'UDPVoiceCELTAlpha', b'UDPPing', b'UDPVoiceSpeex', b'UDPVoiceCELTBeta'
]

MessageTypes = [
	MumbleProto.Version,
	MumbleProto.UDPTunnel,
	MumbleProto.Authenticate,
	MumbleProto.Ping,
	MumbleProto.Reject,
	MumbleProto.ServerSync,
	MumbleProto.ChannelRemove,
	MumbleProto.ChannelState,
	MumbleProto.UserRemove,
	MumbleProto.UserState,
	MumbleProto.BanList,
	MumbleProto.TextMessage,
	MumbleProto.PermissionDenied,
	MumbleProto.ACL,
	MumbleProto.QueryUsers,
	MumbleProto.CryptSetup,
	MumbleProto.ContextActionAdd,
	MumbleProto.ContextAction,
	MumbleProto.UserList,
	MumbleProto.VoiceTarget,
	MumbleProto.PermissionQuery,
	MumbleProto.CodecVersion,
	MumbleProto.UserStats,
	MumbleProto.RequestBlob,
	MumbleProto.ServerConfig
]

HEADER_LENGTH = 6

permissions = Permissions[b'Enter'] | Permissions[b'Speak'] | Permissions[b'Whisper'] | Permissions[b'TextMessage']

def random_bytes(size):
	return b"".join(chr(random.randrange(0, 256)) for i in xrange(size))

connections = []
udpAddrToUser = weakref.WeakValueDictionary()

class Connection(object):
	def __init__(self, sock, addr):
		self.sock = sock
		self.addr = addr
		self.authenticated = False
		self.cs = None
		self.udpSocket = None
		self.udpAddr = None
		self.mute = False
		self.deaf = False
		print b"new connection from %s:%d" % (addr[0], addr[1])
		connections.append(self)
		self.session = connections.index(self) + 1
		stackless.tasklet(self.handle_connection)()

	def send_message(self, msg):
		type = MessageTypes.index(msg.__class__)
		if msg.__class__ != MumbleProto.Ping:
			print b">> " + str(msg.__class__)
			print msg
		length = msg.ByteSize()
		header = struct.pack(b"!hi", type, length)
		data = header + msg.SerializeToString()
		self.sock.send(data)

	def send_tunnel_message(self, msg):
		type = MessageTypes.index(MumbleProto.UDPTunnel)
		length = len(msg)
		header = struct.pack(b"!hi", type, length)
		data = header + b"".join(msg)
		self.sock.send(data)

	def send_all(self, msg):
		for i in connections:
			i.send_message(msg)

	def send_all_except_self(self, msg):
		for i in connections:
			if i == self: continue
			i.send_message(msg)

	def send_tunnel_all_except_self(self, msg):
		for i in connections:
			if i == self or i.deaf == True: continue
			i.send_tunnel_message(msg)

	def send_udp_message(self, msg):
		if not (self.cs and self.cs.valid() and self.udpAddr):
			return
		msg = self.cs.encrypt(msg)
		self.udpSocket.sendto(msg, self.udpAddr)

	def handle_voice_msg(self, packet):
		packet = list(packet)
		udp_type = UDPMessageTypes[(ord(packet[0]) >> 5) & 0x7]
		type = ord(packet[0]) & 0xe0;
		target = ord(packet[0]) & 0x1f;
		data = b'\x00' * 1024
		ps = pds.PDS(data)
		# session
		ps.putInt(1)
		ps.appendDataBlock(packet[1:])
		size = ps.size()
		ps.rewind()
		packet[0] = chr(type | 0)
		packet[1:] = ps.getDataBlock(size)
		self.send_tunnel_all_except_self(packet)

	def handle_connection(self):
		buf = ""
		buffer_length = 0
		while self.sock.connect:
			if buffer_length < HEADER_LENGTH:
				buf = self.sock.recv(4096)
				buffer_length = len(buf)

			if buffer_length < HEADER_LENGTH:
				break

			(msg_type, msg_length) = struct.unpack(b"!hi", buffer(buf, 0, HEADER_LENGTH))
			buf = buffer(buf, HEADER_LENGTH)
			buffer_length -= HEADER_LENGTH

			if buffer_length >= msg_length:
				packet = buffer(buf, 0, msg_length)
				buf = buffer(buf, msg_length)
				buffer_length -= msg_length
			else:
				packet = buf + self.sock.recv(msg_length - buffer_length)
				buf = ""
				buffer_length = 0

			msg = MessageTypes[msg_type]()

			if msg.__class__ != MumbleProto.UDPTunnel:
				msg.ParseFromString(packet)

			if msg.__class__ != MumbleProto.Ping and msg.__class__ != MumbleProto.UDPTunnel:
				print b"<< " + str(msg.__class__)
				print msg

			if msg.__class__ == MumbleProto.Ping:
				self.send_message(msg)

			if msg.__class__ == MumbleProto.Authenticate:
				self.username = msg.username

				error = False
				for i in connections:
					if i == self: continue
					if i.username == self.username:
						r = MumbleProto.Reject()
						r.type = MumbleProto.Reject.UsernameInUse
						self.send_message(r)
						error = True
						break

				if error == True: break

				self.authenticated = True
				r = MumbleProto.Version()
				r.version = (1 << 16 | 2 << 8 | 2 & 0xFF)
				r.release = b"Stackless Server 0.0.0.1"
				r.os = platform.system()
				r.os_version = sys.version
				self.send_message(r)

				self.cs = CryptState()
				key = random_bytes(16)
				cn = random_bytes(16)
				sn = random_bytes(16)
				self.cs.setKey(key, sn, cn)

				r = MumbleProto.CryptSetup()
				r.key = key
				r.client_nonce = cn
				r.server_nonce = sn
				self.send_message(r)

				r = MumbleProto.CodecVersion()
				r.alpha = r.beta = 0x8000000b
				r.prefer_alpha = False
				self.send_message(r)

				r = MumbleProto.ChannelState()
				r.channel_id = 0
				r.name = "Root"
				self.send_message(r)

				for i in connections:
					if i == self: continue
					r = MumbleProto.UserState()
					r.session = i.session
					r.name = i.username
					self.send_message(r)

				r = MumbleProto.UserState()
				r.session = self.session
				r.name = msg.username
				self.send_all(r)

				r = MumbleProto.ServerSync()
				r.session = self.session
				r.max_bandwidth = 240000
				r.permissions = permissions
				self.send_message(r)

			if msg.__class__ == MumbleProto.PermissionQuery:
				msg.permissions = permissions
				self.send_message(msg)

			if msg.__class__ == MumbleProto.TextMessage:
				msg.actor = self.session
				self.send_all_except_self(msg)

			if msg.__class__ == MumbleProto.UserState:
				msg.actor = self.session
				msg.session = self.session
				if msg.HasField(b"self_mute"):
					self.mute = msg.self_mute
				if msg.HasField(b"self_deaf"):
					self.deaf = msg.self_deaf
				self.send_all(msg)

			if msg.__class__ == MumbleProto.UDPTunnel:
				self.handle_voice_msg(packet)

			stackless.schedule()
		print b"Closing connection %s:%d" % (self.addr[0], self.addr[1])
		self.sock.close()
		connections.remove(self)

		if self.authenticated == True:
			r = MumbleProto.UserRemove()
			r.session = self.session
			self.send_all(r)

def tcphandler():
	s = socketlibevent.socket()
	print b"listening..."
	s.bind((b'', 64738))
	s.listen(5)
	while True:
		client_socket, client_address = s.accept()
		ssl_socket = socketlibevent.ssl(client_socket, b"server.key", b"server.pem", True)
		Connection(ssl_socket, client_address)
		stackless.schedule()

def handle_udp_message(u, msg):
	udp_type = UDPMessageTypes[(ord(msg[0]) >> 5) & 0x7]
	if udp_type == b"UDPPing":
#		print "sending ping reply"
		u.send_udp_message(msg)
	else:
		u.handle_voice_msg(msg)

def udphandler():
	s = socketlibevent.socket(socket.AF_INET, socket.SOCK_DGRAM)
	print b"starting udp handler..."
	s.bind((b'', 64738))
	while True:
		(buf, addr) = s.recvfrom(4096)
		if len(buf) == 12:
			r = struct.unpack(b"!iQ", buf)
			if r[0] != 0: continue
			r = struct.pack(b"!iQiii", (1 << 16 | 2 << 8 | 2 & 0xFF), r[1], len(connections), -1, 240000)
			s.sendto(r, 0, addr)
		else:
			if addr in udpAddrToUser:
				if not u.cs or not u.cs.valid():
					continue
				u = udpAddrToUser[addr]
#				print "UDP: packet from known user %d" % (u.session)
				buf = u.cs.decrypt(buf)
				if buf != False:
					handle_udp_message(u, buf)
			else:
				u = None
				for usr in connections:
					if usr.cs and usr.cs.valid():
						r = usr.cs.decrypt(buf)
						if r == False:
							continue

#						print "UDP: found user %d" % (usr.session)
						usr.udpSocket = s
						usr.udpAddr = addr
						udpAddrToUser[addr] = usr
						u = usr
						buf = r
						break

				if not u:
					print addr
					print binascii.hexlify(buf)
				else:
					handle_udp_message(u, buf)

if __name__ == '__main__':
	stackless.tasklet(tcphandler)()
	stackless.tasklet(udphandler)()
	stackless.run()
