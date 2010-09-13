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


sys.modules['socket'] = socketlibevent

permissions = Permissions['Enter'] | Permissions['Speak'] | Permissions['Whisper'] | Permissions['TextMessage']

def random_bytes(size):
	return "".join(chr(random.randrange(0, 256)) for i in xrange(size))

def send_message(sock, msg):
	type = MessageTypes.index(msg.__class__)
	if msg.__class__ != MumbleProto.Ping:
		print ">> " + str(msg.__class__)
		print msg
	length = msg.ByteSize()
	header = struct.pack("!hi", type, length)
	data = header + msg.SerializeToString()
	sock.send(data)

def send_tunnel_message(sock, msg):
	type = MessageTypes.index(MumbleProto.UDPTunnel)
	length = len(msg)
	header = struct.pack("!hi", type, length)
	data = header + "".join(msg)
	sock.send(data)

def handle_connection(cs, la):
	while cs.connect:
		h_buffer = cs.recv(6)
		if len(h_buffer) < 6: break
		header = struct.unpack("!hi", h_buffer)
		# print "Header - type: %d length: %d" % (header[0], header[1])
		# 0 = type
		# 1 = length
		packet = cs.recv(header[1])
		msg = MessageTypes[header[0]]()

		if msg.__class__ != MumbleProto.UDPTunnel:
			msg.ParseFromString(packet)

		if msg.__class__ != MumbleProto.Ping and msg.__class__ != MumbleProto.UDPTunnel:
			print "<< " + str(msg.__class__)
			print msg

		if msg.__class__ == MumbleProto.Ping:
			send_message(cs, msg)

		if msg.__class__ == MumbleProto.Authenticate:
			r = MumbleProto.Version()
			r.version = (1 << 16 | 2 << 8 | 2 & 0xFF)
			r.release = "Stackless Server 0.0.0.1"
			r.os = platform.system()
			r.os_version = sys.version
			send_message(cs, r)

			r = MumbleProto.CryptSetup()
			r.key = random_bytes(16)
			r.client_nonce = random_bytes(16)
			r.server_nonce = random_bytes(16)
			send_message(cs, r)

			r = MumbleProto.CodecVersion()
			r.alpha = r.beta = 0x8000000b
			r.prefer_alpha = False
			send_message(cs, r)

			r = MumbleProto.ChannelState()
			r.channel_id = 0
			r.name = "Root"
			send_message(cs, r)

			r = MumbleProto.UserState()
			r.session = 1
			r.name = "pcgod"
			send_message(cs, r)

			r = MumbleProto.ServerSync()
			r.session = 1
			r.max_bandwidth = 240000
			r.permissions = permissions
			send_message(cs, r)

		if msg.__class__ == MumbleProto.PermissionQuery:
			msg.permissions = permissions
			send_message(cs, msg)

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
			send_tunnel_message(cs, packet)

		stackless.schedule()
	print "Closing connection %s:%d" % (la[0], la[1])
	cs.close()

def run():
	s = socketlibevent.socket()
	print "listening..."
	s.bind(('', 64738))
	s.listen(5)
	while True:
		client_socket, client_address = s.accept()
		ssl_socket = socketlibevent.ssl(client_socket, "server.key", "server.pem", True)
		print "accepting connection from %s:%d" % (client_address[0], client_address[1])
		#stackless.tasklet(handle_connection)(client_socket, client_address)
		stackless.tasklet(handle_connection)(ssl_socket, client_address)
		stackless.schedule()


if __name__ == '__main__':
	run()
