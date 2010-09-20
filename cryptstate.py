#!/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, unicode_literals

from Crypto.Cipher import AES
import binascii
import struct


def _bswap32(x):
	return	((x & 0x000000FF) << 24) | ((x & 0x0000FF00) <<  8) | \
			((x & 0x00FF0000) >>  8) | ((x & 0xFF000000) >> 24)

def _bswap64(x):
	return	((x >> 56) & 0x00000000000000FF) | ((x >> 40) & 0x000000000000FF00) | \
			((x >> 24) & 0x0000000000FF0000) | ((x >>  8) & 0x00000000FF000000) | \
			((x <<  8) & 0x000000FF00000000) | ((x << 24) & 0x0000FF0000000000) | \
			((x << 40) & 0x00FF000000000000) | ((x << 56) & 0xFF00000000000000)


_BLOCKSIZE = 4
_BLOCKFMT = b'<%dI'
_SHIFTBITS = 31
_bswap = _bswap32

#_BLOCKSIZE = 2
#_BLOCKFMT = b'<%dQ'
#_SHIFTBITS = 63
#_bswap = _bswap64

_AES_BLOCK_SIZE = AES.block_size
_FMTSIZE = struct.calcsize(_BLOCKFMT % (1))

def _XOR(d, a, b):
	d[0] = a[0] ^ b[0]
	d[1] = a[1] ^ b[1]
	d[2] = a[2] ^ b[2]
	d[3] = a[3] ^ b[3]

def _S2(block):
	block[0] = _bswap(block[0])
	block[1] = _bswap(block[1])
	block[2] = _bswap(block[2])
	block[3] = _bswap(block[3])

	carry = block[0] >> _SHIFTBITS
	block[0] = (block[0] << 1) | (block[1] >> _SHIFTBITS)
	block[1] = (block[1] << 1) | (block[2] >> _SHIFTBITS)
	block[2] = (block[2] << 1) | (block[3] >> _SHIFTBITS)
	block[3] = (block[3] << 1) ^ (carry * 0x87)

	block[0] = _bswap(block[0])
	block[1] = _bswap(block[1])
	block[2] = _bswap(block[2])
	block[3] = _bswap(block[3])

def _S3(block):
	block[0] = _bswap(block[0])
	block[1] = _bswap(block[1])
	block[2] = _bswap(block[2])
	block[3] = _bswap(block[3])

	carry = block[0] >> _SHIFTBITS
	block[0] ^= (block[0] << 1) | (block[1] >> _SHIFTBITS)
	block[1] ^= (block[1] << 1) | (block[2] >> _SHIFTBITS)
	block[2] ^= (block[2] << 1) | (block[3] >> _SHIFTBITS)
	block[3] ^= (block[3] << 1) ^ (carry * 0x87)

	block[0] = _bswap(block[0])
	block[1] = _bswap(block[1])
	block[2] = _bswap(block[2])
	block[3] = _bswap(block[3])

def _ZERO(block):
	block[0] = 0
	block[1] = 0
	block[2] = 0
	block[3] = 0

class CryptState(object):
	def __init__(self):
		self._decrypt_history = [b'\x00'] * 256
		self.uiGood = 0
		self.uiLate = 0
		self.uiLost = 0
		self.init = False

	def isValid(self):
		return self.init

	def setKey(self, raw_key, encrypt_iv, decrypt_iv):
		self.raw_key = raw_key
		self._encrypt_iv = list(encrypt_iv)
		self._decrypt_iv = list(decrypt_iv)
		self.aes = AES.new(raw_key, AES.MODE_ECB)
		self.init = True

	def encrypt(self, src):
		for i in range(0, _AES_BLOCK_SIZE - 1):
			self._encrypt_iv[i] = chr((ord(self._encrypt_iv[i]) + 1) % 256)
			if ord(self._encrypt_iv[i]) != 0:
				break

		enc, enctag = self.ocb_encrypt(src, self._encrypt_iv)
		enc_str = struct.pack(_BLOCKFMT % len(enc), *enc)
		enctag_str = struct.pack(_BLOCKFMT % len(enctag), *enctag)

		dst = self._encrypt_iv[0] + enctag_str[:3] + enc_str
		return dst

	def decrypt(self, src):
		if len(src) < 4:
			return False

		ivbyte = ord(src[0])
		decivbyte = ord(self._decrypt_iv[0])
		restore = False

		lost = 0
		late = 0

		saveiv = self._decrypt_iv

		if ((decivbyte + 1) & 0xFF) == ivbyte:
			if ivbyte > decivbyte:
				self._decrypt_iv[0] = chr(ivbyte)
			elif ivbyte < decivbyte:
				self._decrypt_iv[0] = chr(ivbyte)
				for i in range(1, _AES_BLOCK_SIZE - 1):
					self._decrypt_iv[i] = chr((ord(self._decrypt_iv[i]) + 1) % 256)
					if ord(self._decrypt_iv[i]) != 0:
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
				self._decrypt_iv[0] = chr(ivbyte)
				restore = True
			elif (ivbyte > decivbyte) and (diff > -30) and (diff < 0):
				late = 1
				lost = -1
				self.decryt_iv[0] = chr(ivbyte)

				# TODO: check if this is correct
				for i in range(1, _AES_BLOCK_SIZE - 1):
					self._decrypt_iv[i] = chr((ord(self._decrypt_iv[i]) - 1) % 256)
					if ((ord(self._decrypt_iv[i]) + 1) % 256) != 0:
						break
				restore = True
			elif (ivbyte > decivbyte) and (diff > 0):
				lost = ivbyte - decivbyte - 1
				self._decrypt_iv[0] = chr(ivbyte)
			elif (ivbyte < decivbyte) and (diff > 0):
				lost = 256 - decivbyte + ivbyte - 1
				self._decrypt_iv[0] = chr(ivbyte)
				for i in range(1, _AES_BLOCK_SIZE - 1):
					self._decrypt_iv[i] = chr((ord(self._decrypt_iv[i]) + 1) % 256)
					if ord(self._decrypt_iv[i]) != 0:
						break
			else:
				return False

			if self._decrypt_history[ord(self._decrypt_iv[0])] == self._decrypt_iv[1]:
				self._decrypt_iv = saveiv
				return False

		(dec, dectag) = self.ocb_decrypt(src[4:], self._decrypt_iv)
		dec_str = struct.pack(_BLOCKFMT % len(dec), *dec)
		dectag_str = struct.pack(_BLOCKFMT % len(dectag), *dectag)

		if dectag_str[:3] != src[1:4]:
			self._decrypt_iv = saveiv
			return False

		self._decrypt_history[ord(self._decrypt_iv[0])] = self._decrypt_iv[1]

		if restore:
			self._decrypt_iv = saveiv

		self.uiGood += 1
		self.uiLate += late
		self.uiLost += lost

		return dec_str

	def ocb_encrypt(self, src, nonce):
		checksum = [0] * _BLOCKSIZE
		tmp = [0] * _BLOCKSIZE
		encrypted = []

		delta = list(struct.unpack(_BLOCKFMT % _BLOCKSIZE, self.aes.encrypt(b"".join(nonce))))
		offset = 0
		length = len(src)

		if length > _AES_BLOCK_SIZE:
			src_cnt = len(src) // _AES_BLOCK_SIZE
			src_unpacked = list(struct.unpack(_BLOCKFMT % (src_cnt * (_AES_BLOCK_SIZE // _FMTSIZE)), src[:src_cnt * _AES_BLOCK_SIZE]))

		while length > _AES_BLOCK_SIZE:
			_S2(delta)
			_XOR(tmp, delta, src_unpacked[offset // _AES_BLOCK_SIZE * _BLOCKSIZE:offset // _AES_BLOCK_SIZE * _BLOCKSIZE + _BLOCKSIZE])
			tmp = list(struct.unpack(_BLOCKFMT % (_BLOCKSIZE), self.aes.encrypt(struct.pack(_BLOCKFMT % (_BLOCKSIZE), *tmp))))
			tmp_block = [0] * _BLOCKSIZE
			_XOR(tmp_block, delta, tmp)
			encrypted += tmp_block
			_XOR(checksum, checksum, src_unpacked[offset // _AES_BLOCK_SIZE * _BLOCKSIZE:offset // _AES_BLOCK_SIZE * _BLOCKSIZE + _BLOCKSIZE])
			length -= _AES_BLOCK_SIZE
			offset += _AES_BLOCK_SIZE

		_S2(delta)
		_ZERO(tmp)
		tmp[_BLOCKSIZE - 1] = _bswap(length * 8)
		_XOR(tmp, tmp, delta)
		pad = list(struct.unpack(_BLOCKFMT % (_BLOCKSIZE), self.aes.encrypt(struct.pack(_BLOCKFMT % (_BLOCKSIZE), *tmp))))
		padbytes = list(struct.pack(_BLOCKFMT % (_BLOCKSIZE), *pad))
		tmp = list(struct.unpack(_BLOCKFMT % (_BLOCKSIZE), b"".join(src[offset:offset + length] + b"".join(padbytes[length:_AES_BLOCK_SIZE]))))
		_XOR(checksum, checksum, tmp)
		_XOR(tmp, pad, tmp)
		encrypted += tmp[0:length // _BLOCKSIZE]
		_S3(delta)
		_XOR(tmp, delta, checksum)
		tag = list(struct.unpack(_BLOCKFMT % (_BLOCKSIZE), self.aes.encrypt(struct.pack(_BLOCKFMT % (_BLOCKSIZE), *tmp))))
		return encrypted, tag

	def ocb_decrypt(self, src, nonce):
		checksum = [0] * _BLOCKSIZE
		tmp = [0] * _BLOCKSIZE
		plain = []

		delta = list(struct.unpack(_BLOCKFMT % _BLOCKSIZE, self.aes.encrypt(b"".join(nonce))))
		offset = 0
		length = len(src)

		if length > _AES_BLOCK_SIZE:
			src_cnt = len(src) // _AES_BLOCK_SIZE
			src_unpacked = list(struct.unpack(_BLOCKFMT % (src_cnt * (_AES_BLOCK_SIZE // _FMTSIZE)), src[:src_cnt * _AES_BLOCK_SIZE]))

		while length > _AES_BLOCK_SIZE:
			_S2(delta)
			_XOR(tmp, delta, src_unpacked[offset // _AES_BLOCK_SIZE * _BLOCKSIZE:offset // _AES_BLOCK_SIZE * _BLOCKSIZE + _BLOCKSIZE])
			tmp = list(struct.unpack(_BLOCKFMT % (_BLOCKSIZE), self.aes.decrypt(struct.pack(_BLOCKFMT % (_BLOCKSIZE), *tmp))))
			tmp_block = [0] * _BLOCKSIZE
			_XOR(tmp_block, delta, tmp)
			plain += tmp_block
			_XOR(checksum, checksum, tmp_block)
			length -= _AES_BLOCK_SIZE
			offset += _AES_BLOCK_SIZE

		_S2(delta)
		_ZERO(tmp)
		tmp[_BLOCKSIZE - 1] = _bswap(length * 8)
		_XOR(tmp, tmp, delta)
		pad = list(struct.unpack(_BLOCKFMT % _BLOCKSIZE, self.aes.encrypt(struct.pack(_BLOCKFMT % _BLOCKSIZE, *tmp))))
		_ZERO(tmp)
		tmp = list(struct.unpack(_BLOCKFMT % _BLOCKSIZE, b"".join(src[offset:offset + length] + (b'\x00' * (_AES_BLOCK_SIZE - length)))))
		_XOR(tmp, tmp, pad);
		_XOR(checksum, checksum, tmp);
		plain += tmp[0:length // _BLOCKSIZE]
		_S3(delta)
		_XOR(tmp, delta, checksum)
		tag = list(struct.unpack(_BLOCKFMT % _BLOCKSIZE, self.aes.encrypt(struct.pack(_BLOCKFMT % _BLOCKSIZE, *tmp))))
		return plain, tag

if __name__ == '__main__':
#	import sys
#	import timeit

#	t = timeit.Timer("_S3(x)", "from __main__ import _S3; x = [123, 456, 789, 123]")
#	r = t.timeit()
#	print r
#	print "%.2f usec/pass" % (1000000 * r / 100000)

#	t = timeit.Timer("_S3_2(x)", "from __main__ import _S3_2; x = [123, 456, 789, 123]")
#	r = t.timeit()
#	print r
#	print "%.2f usec/pass" % (1000000 * r / 100000)

#	t = timeit.Timer("_S3_4(x)", "from __main__ import _S3_4; x = [123, 456, 789, 123]")
#	r = t.timeit()
#	print r
#	print "%.2f usec/pass" % (1000000 * r / 100000)

#	sys.exit()

	rawkey = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
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
		print(binascii.hexlify(x))
		if y != False:
			print(binascii.hexlify(y))
		else:
			print("Decrypt error")

	print(cs.uiGood, cs.uiLate, cs.uiLost)

#	const unsigned char longtag[_AES_BLOCK_SIZE] = {0x9D,0xB0,0xCD,0xF8,0x80,0xF7,0x3E,0x3E,0x10,0xD4,0xEB,0x32,0x17,0x76,0x66,0x88};
#	const unsigned char crypted[40] = {0xF7,0x5D,0x6B,0xC8,0xB4,0xDC,0x8D,0x66,0xB8,0x36,0xA2,0xB0,0x8B,0x32,0xA6,0x36,0x9F,0x1C,0xD3,0xC5,0x22,0x8D,0x79,0xFD,
#										0x6C,0x26,0x7F,0x5F,0x6A,0xA7,0xB2,0x31,0xC7,0xDF,0xB9,0xD5,0x99,0x51,0xAE,0x9C};
