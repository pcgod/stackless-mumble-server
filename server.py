#!/usr/local/bin/spython -OO

import os
import sys
import struct
import stackless
#import stacklesssocket
import socketlibevent
import random
import platform
import Mumble_pb2 as MumbleProto

import pds

sys.modules['socket'] = socketlibevent

Permissions = {
	'None': 0x0,
	'Write': 0x1,
	'Traverse': 0x2,
	'Enter': 0x4,
	'Speak': 0x8,
	'MuteDeafen': 0x10,
	'Move': 0x20,
	'MakeChannel': 0x40,
	'LinkChannel': 0x80,
	'Whisper': 0x100,
	'TextMessage': 0x200,
	'MakeTempChannel': 0x400,

	# Root channel only
	'Kick': 0x10000,
	'Ban': 0x20000,
	'Register': 0x40000,
	'SelfRegister': 0x80000,

	'Cached': 0x8000000,
	'All': 0xf07ff
}

UDPMessageTypes = [
	'UDPVoiceCELTAlpha', 'UDPPing', 'UDPVoiceSpeex', 'UDPVoiceCELTBeta'
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


permissions = Permissions['Enter'] | Permissions['Speak'] | Permissions['Whisper'] | Permissions['TextMessage']

def random_bytes(size):
	return "".join(chr(random.randrange(0, 256)) for i in xrange(size))

connections = []

class Connection(object):
	def __init__(self, sock, addr):
		self.sock = sock
		self.addr = addr
		self.authenticated = False
		print "new connection from %s:%d" % (addr[0], addr[1])
		connections.append(self)
		self.session = connections.index(self) + 1
		stackless.tasklet(self.handle_connection)()

	def send_message(self, msg):
		type = MessageTypes.index(msg.__class__)
		if msg.__class__ != MumbleProto.Ping:
			print ">> " + str(msg.__class__)
			print msg
		length = msg.ByteSize()
		header = struct.pack("!hi", type, length)
		data = header + msg.SerializeToString()
		self.sock.send(data)

	def send_tunnel_message(self, msg):
		type = MessageTypes.index(MumbleProto.UDPTunnel)
		length = len(msg)
		header = struct.pack("!hi", type, length)
		data = header + "".join(msg)
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
			if i == self: continue
			i.send_tunnel_message(msg)

	def handle_connection(self):
		while self.sock.connect:
			h_buffer = self.sock.recv(6)
			if len(h_buffer) < 6: break
			header = struct.unpack("!hi", h_buffer)
			# print "Header - type: %d length: %d" % (header[0], header[1])
			# 0 = type
			# 1 = length
			packet = self.sock.recv(header[1])
			msg = MessageTypes[header[0]]()

			if msg.__class__ != MumbleProto.UDPTunnel:
				msg.ParseFromString(packet)

			if msg.__class__ != MumbleProto.Ping and msg.__class__ != MumbleProto.UDPTunnel:
				print "<< " + str(msg.__class__)
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
				r.release = "Stackless Server 0.0.0.1"
				r.os = platform.system()
				r.os_version = sys.version
				self.send_message(r)

				r = MumbleProto.CryptSetup()
				r.key = random_bytes(16)
				r.client_nonce = random_bytes(16)
				r.server_nonce = random_bytes(16)
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

			if msg.__class__ == MumbleProto.UDPTunnel:
				packet = list(packet)
				udp_type = UDPMessageTypes[(ord(packet[0]) >> 5) & 0x7]
				type = ord(packet[0]) & 0xe0;
				target = ord(packet[0]) & 0x1f;
				data = '\x00' * 1024
				ps = pds.PDS(data)
				# session
				ps.putInt(1)
				ps.appendDataBlock(packet[1:len(packet) - 1])
				size = ps.size()
				ps.rewind()
				packet[0] = chr(type | 0)
				packet[1:] = ps.getDataBlock(size)
				self.send_tunnel_all_except_self(packet)

			stackless.schedule()
		print "Closing connection %s:%d" % (self.addr[0], self.addr[1])
		self.sock.close()
		connections.remove(self)

		if self.authenticated == True:
			r = MumbleProto.UserRemove()
			r.session = self.session
			self.send_all(r)

def run():
	s = socketlibevent.socket()
	print "listening..."
	s.bind(('', 64738))
	s.listen(5)
	while True:
		client_socket, client_address = s.accept()
		ssl_socket = socketlibevent.ssl(client_socket, "server.key", "server.pem", True)
		Connection(ssl_socket, client_address)
		stackless.schedule()


if __name__ == '__main__':
	run()
