#!/bin/env python
# -*- coding: utf-8 -*-

from Crypto.Cipher import AES
import binascii
import struct

AES_BLOCK_SIZE = AES.block_size
BLOCKSIZE = 4
SHIFTBITS = 31

def bswap32(x):
	return ((x & 0x000000FF) << 24) | ((x & 0x0000FF00) << 8) | ((x & 0x00FF0000) >> 8) | ((x & 0xFF000000) >> 24)

def XOR(d, a, b):
	for i in range(0, BLOCKSIZE):
		d[i] = a[i] ^ b[i]

def S2(block):
	carry = bswap32(block[0]) >> SHIFTBITS
	for i in range(0, BLOCKSIZE - 1):
		block[i] = bswap32((bswap32(block[i]) << 1) | (bswap32(block[i + 1]) >> SHIFTBITS))
	block[BLOCKSIZE - 1] = bswap32((bswap32(block[BLOCKSIZE - 1]) << 1) ^ (carry * 0x87))

def S3(block):
	carry = bswap32(block[0]) >> SHIFTBITS
	for i in range(0, BLOCKSIZE - 1):
		block[i] ^= bswap32((bswap32(block[i]) << 1) | (bswap32(block[i + 1]) >> SHIFTBITS))
	block[BLOCKSIZE - 1] ^= bswap32((bswap32(block[BLOCKSIZE - 1]) << 1) ^ (carry * 0x87))

def ZERO(block):
	for i in range(0, BLOCKSIZE):
		block[i] = 0

class CryptState(object):
	def __init__(self):
		self.decrypt_history = ['\x00'] * 256
		self.uiGood = 0
		self.uiLate = 0
		self.uiLost = 0
		self.init = False

	def valid(self):
		return self.init

	def setKey(self, raw_key, encrypt_iv, decrypt_iv):
		self.raw_key = raw_key
		self.encrypt_iv = list(encrypt_iv)
		self.decrypt_iv = list(decrypt_iv)
		self.aes = AES.new(raw_key, AES.MODE_ECB)
		self.init = True

	def encrypt(self, src):
		for i in range(0, AES_BLOCK_SIZE - 1):
			self.encrypt_iv[i] = chr((ord(self.encrypt_iv[i]) + 1) % 256)
			if ord(self.encrypt_iv[i]) != 0:
				break

		enc, enctag = self.ocb_encrypt(src, self.encrypt_iv)
		enc_str = struct.pack("".join(["I"] * len(enc)), *enc)
		enctag_str = struct.pack("".join(["I"] * len(enctag)), *enctag)

		dst = self.encrypt_iv[0] + enctag_str[:3] + enc_str
		return dst

	def decrypt(self, src):
		if len(src) < 4:
			return False

		ivbyte = ord(src[0])
		decivbyte = ord(self.decrypt_iv[0])
		restore = False

		lost = 0
		late = 0

		saveiv = self.decrypt_iv

		if ((decivbyte + 1) & 0xFF) == ivbyte:
			if ivbyte > decivbyte:
				self.decrypt_iv[0] = chr(ivbyte)
			elif ivbyte < decivbyte:
				self.decrypt_iv[0] = chr(ivbyte)
				for i in range(1, AES_BLOCK_SIZE - 1):
					self.decrypt_iv[i] = chr((ord(self.decrypt_iv[i]) + 1) % 256)
					if ord(self.decrypt_iv[i]) != 0:
						break
			else:
				return False
		else:
			diff = ivbyte - decivbyte
			if diff > 128:
				diff -= 256
			elif diff < -128:
				diff += 256

			if (ivbyte < decivbyte) and (diff > -30) and (diff < 0):
				late = 1
				lost = -1
				self.decrypt_iv[0] = chr(ivbyte)
				restore = True
			elif (ivbyte > decivbyte) and (diff > -30) and (diff < 0):
				late = 1
				lost = -1
				self.decryt_iv[0] = chr(ivbyte)

				# TODO: check if this is correct
				for i in range(1, AES_BLOCK_SIZE - 1):
					self.decrypt_iv[i] = chr((ord(self.decrypt_iv[i]) - 1) % 256)
					if ((ord(self.decrypt_iv[i]) + 1) % 256) != 0:
						break
				restore = True
			elif (ivbyte > decivbyte) and (diff > 0):
				lost = ivbyte - decivbyte - 1
				self.decrypt_iv[0] = chr(ivbyte)
			elif (ivbyte < decivbyte) and (diff > 0):
				lost = 256 - decivbyte + ivbyte - 1
				self.decrypt_iv[0] = chr(ivbyte)
				for i in range(1, AES_BLOCK_SIZE - 1):
					self.decrypt_iv[i] = chr((ord(self.decrypt_iv[i]) + 1) % 256)
					if ord(self.decrypt_iv[i]) != 0:
						break
			else:
				return False

			if self.decrypt_history[ord(self.decrypt_iv[0])] == self.decrypt_iv[1]:
				self.decrypt_iv = saveiv
				return False

		(dec, dectag) = self.ocb_decrypt(src[4:], self.decrypt_iv)
		dec_str = struct.pack("".join(["I"] * len(dec)), *dec)
		dectag_str = struct.pack("".join(["I"] * len(dectag)), *dectag)

		if dectag_str[:3] != src[1:4]:
			self.decrypt_iv = saveiv
			return False

		self.decrypt_history[ord(self.decrypt_iv[0])] = self.decrypt_iv[1]

		if restore:
			self.decrypt_iv = saveiv

		self.uiGood += 1
		self.uiLate += late
		self.uiLost += lost

		return dec_str

	def ocb_encrypt(self, src, nonce):
		checksum = [0] * (AES_BLOCK_SIZE / BLOCKSIZE)
		tmp = [0] * (AES_BLOCK_SIZE / BLOCKSIZE)
		encrypted = []

		delta = list(struct.unpack("IIII", self.aes.encrypt("".join(nonce))))
		offset = 0
		length = len(src)

		while length > AES_BLOCK_SIZE:
			S2(delta)
			XOR(tmp, delta, list(struct.unpack("IIII", "".join(src[offset:offset + AES_BLOCK_SIZE]))))
			tmp = list(struct.unpack("IIII", self.aes.encrypt(struct.pack("IIII", *tmp))))
			tmp_block = [0 for i in range(AES_BLOCK_SIZE / BLOCKSIZE)]
			XOR(tmp_block, delta, tmp)
			encrypted += tmp_block
			XOR(checksum, checksum, list(struct.unpack("IIII", "".join(src[offset:offset + AES_BLOCK_SIZE]))))
			length -= AES_BLOCK_SIZE
			offset += AES_BLOCK_SIZE

		S2(delta)
		ZERO(tmp)
		tmp[BLOCKSIZE - 1] = bswap32(length * 8)
		XOR(tmp, tmp, delta)
		pad = list(struct.unpack("IIII", self.aes.encrypt(struct.pack("IIII", *tmp))))
		padbytes = list(struct.pack("IIII", *pad))
		tmp = list(struct.unpack("IIII", "".join(src[offset:offset + length] + "".join(padbytes[length:AES_BLOCK_SIZE]))))
		XOR(checksum, checksum, tmp)
		XOR(tmp, pad, tmp)
		encrypted += tmp[0:length / BLOCKSIZE]
		S3(delta)
		XOR(tmp, delta, checksum)
		tag = list(struct.unpack("IIII", self.aes.encrypt(struct.pack("IIII", *tmp))))
		return encrypted, tag

	def ocb_decrypt(self, src, nonce):
		checksum = [0] * (AES_BLOCK_SIZE / BLOCKSIZE)
		tmp = [0] * (AES_BLOCK_SIZE / BLOCKSIZE)
		plain = []

		delta = list(struct.unpack("IIII", self.aes.encrypt("".join(nonce))))
		offset = 0
		length = len(src)

		while length > AES_BLOCK_SIZE:
			S2(delta)
			XOR(tmp, delta, list(struct.unpack("IIII", "".join(src[offset:offset + AES_BLOCK_SIZE]))))
			tmp = list(struct.unpack("IIII", self.aes.decrypt(struct.pack("IIII", *tmp))))
			tmp_block = [0 for i in range(AES_BLOCK_SIZE / BLOCKSIZE)]
			XOR(tmp_block, delta, tmp)
			plain += tmp_block
			XOR(checksum, checksum, tmp_block)
			length -= AES_BLOCK_SIZE
			offset += AES_BLOCK_SIZE

		S2(delta)
		ZERO(tmp)
		tmp[BLOCKSIZE - 1] = bswap32(length * 8)
		XOR(tmp, tmp, delta)
		pad = list(struct.unpack("IIII", self.aes.encrypt(struct.pack("IIII", *tmp))))
		ZERO(tmp)
		tmp = list(struct.unpack("IIII", "".join(src[offset:offset + length] + ('\x00' * (AES_BLOCK_SIZE - length)))))
		XOR(tmp, tmp, pad);
		XOR(checksum, checksum, tmp);
		plain += tmp[0:length / BLOCKSIZE]
		S3(delta)
		XOR(tmp, delta, checksum)
		tag = list(struct.unpack("IIII", self.aes.encrypt(struct.pack("IIII", *tmp))))
		return plain, tag

if __name__ == '__main__':
	rawkey = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
	cs = CryptState()
	cs.setKey(rawkey, rawkey, rawkey)
#	res = [0xBF,0x31,0x08,0x13, 0x07,0x73,0xAD,0x5E, 0xC7,0x0E,0xC6,0x9E, 0x78,0x75,0xA7,0xB0]
#	r = cs.ocb_encrypt([], rawkey)
#	print binascii.hexlify(struct.pack("IIII", *r[1]))
#	print r

#	source = [chr(i) for i in range(40)]
#	print "source: " + binascii.hexlify("".join(source))
#	(enc, enctag) = cs.ocb_encrypt(source, rawkey);

#	enc_str = struct.pack("".join(["I" for i in range(len(enc))]), *enc)
#	enctag_str = struct.pack("".join(["I" for i in range(len(enctag))]), *enctag)
#	print "encrypted: " + binascii.hexlify(enc_str)
#	print "encrypt tag: " + binascii.hexlify(enctag_str)
##	print enc, enctag

#	print ""

#	(dec, dectag) = cs.ocb_decrypt(enc_str, rawkey)
#	dec_str = struct.pack("".join(["I" for i in range(len(dec))]), *dec)
#	dectag_str = struct.pack("".join(["I" for i in range(len(dectag))]), *dectag)
#	print "decrypted: " + binascii.hexlify(dec_str)
#	print "decrypt tag: " + binascii.hexlify(dectag_str)
##	print dec, dectag

	for i in range(300):
		x = cs.encrypt(rawkey)
		y = cs.decrypt(x)
		print binascii.hexlify(x)
		if y != False:
			print binascii.hexlify(y)
		else:
			print "Decrypt error"

	print cs.uiGood, cs.uiLate, cs.uiLost

#	const unsigned char longtag[AES_BLOCK_SIZE] = {0x9D,0xB0,0xCD,0xF8,0x80,0xF7,0x3E,0x3E,0x10,0xD4,0xEB,0x32,0x17,0x76,0x66,0x88};
#	const unsigned char crypted[40] = {0xF7,0x5D,0x6B,0xC8,0xB4,0xDC,0x8D,0x66,0xB8,0x36,0xA2,0xB0,0x8B,0x32,0xA6,0x36,0x9F,0x1C,0xD3,0xC5,0x22,0x8D,0x79,0xFD,
#										0x6C,0x26,0x7F,0x5F,0x6A,0xA7,0xB2,0x31,0xC7,0xDF,0xB9,0xD5,0x99,0x51,0xAE,0x9C};
