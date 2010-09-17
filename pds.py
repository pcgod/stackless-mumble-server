#!/bin/env python

class PDS(object):
	def __init__(self, data):
		self._data = list(data)
		self._pos = 0
		self._ok = True
		self._capacity = len(data)

	def valid(self):
		return self._ok

	def size(self):
		return self._pos

	def left(self):
		return self._capacity - self._pos

	def append(self, value):
		if (self._pos < self._capacity):
			self._data[self._pos] = chr(value)
			self._pos += 1
		else:
			self._ok = False

	def appendDataBlock(self, data):
		length = len(data)
		if length <= self.left():
			self._data[self._pos:self._pos + length] = data
			self._pos += length
		else:
			self._ok = False

	def next(self):
		if (self._pos < self._capacity):
			ret = ord(self._data[self._pos])
			self._pos += 1
			return ret
		else:
			self._ok = False
			return 0

	def rewind(self):
		self._pos = 0

	def skip(self, length):
		if length <= self.left():
			self._pos += length
		else:
			self._ok = False

	def getDataBlock(self, length):
		if length <= self.left():
			data = self._data[self._pos:self._pos + length]
			self._pos += length
			return data
		else:
			self._ok = False
			return []

	def getInt(self):
		v = self.next()
		i = 0

		if (v & 0x80) == 0x00:
			i = v & 0x7F
		elif (v & 0xC0) == 0x80:
			i = (v & 0x3F) << 8 | self.next()
		elif (v & 0xF0) == 0xF0:
			x = v & 0xFC
			if x == 0xF0:
				i = self.next() << 24 | self.next() << 16 | self.next() << 8 | self.next()
			elif x == 0xF4:
				i = self.next() << 56 | self.next() << 48 | self.next() << 40 | self.next() << 32 | self.next() << 24 | self.next() << 16 | self.next() << 8 | self.next()
			elif x == 0xF8:
				i = self.getInt()
				i = ~i
			elif x == 0xFC:
				i = v & 0x03
				i = ~i
			else:
				ok = False
				i = 0
		elif (v & 0xF0) == 0xE0:
			i = (v & 0x0F) << 24 | self.next() << 16 | self.next() << 8 | self.next()
		elif (v & 0xE0) == 0xC0:
			i =(v & 0x1F) << 16 | self.next() << 8 | self.next()

		return i

	def putInt(self, value):
		i = value;

		if (i & 0x8000000000000000) and (~i < 0x100000000):
			i = ~i;
			if i <= 0x3:
				# Shortcase for -1 to -4
				self.append(0xFC | i);
			else:
				self.append(0xF8);
		if i < 0x80:
			# Need top bit clear
			self.append(i);
		elif i < 0x4000:
			# Need top two bits clear
			self.append((i >> 8) | 0x80);
			self.append(i & 0xFF);
		elif i < 0x200000:
			# Need top three bits clear
			self.append((i >> 16) | 0xC0);
			self.append((i >> 8) & 0xFF);
			self.append(i & 0xFF);
		elif i < 0x10000000:
			# Need top four bits clear
			self.append((i >> 24) | 0xE0);
			self.append((i >> 16) & 0xFF);
			self.append((i >> 8) & 0xFF);
			self.append(i & 0xFF);
		elif i < 0x100000000:
			# It's a full 32-bit integer.
			self.append(0xF0);
			self.append((i >> 24) & 0xFF);
			self.append((i >> 16) & 0xFF);
			self.append((i >> 8) & 0xFF);
			self.append(i & 0xFF);
		else:
			# It's a 64-bit value.
			self.append(0xF4);
			self.append((i >> 56) & 0xFF);
			self.append((i >> 48) & 0xFF);
			self.append((i >> 40) & 0xFF);
			self.append((i >> 32) & 0xFF);
			self.append((i >> 24) & 0xFF);
			self.append((i >> 16) & 0xFF);
			self.append((i >> 8) & 0xFF);
			self.append(i & 0xFF);


if __name__ == '__main__':
#	data_arr = [0x00, 0x13, 0x00, 0xF8, 0xDF, 0xF7, 0xDA, 0x15, 0x98, 0x9D, 0x67, 0xD1, 0xA2, 0xCC, 0xA3, 0x54, 0x91, 0x6E, 0xBE, 0xA1, 0x17, 0x44, 0x7A, 0x0D, 0x85, 0x27, 0xF4, 0x39, 0xF4, 0xA2, 0x44, 0x35]
#	data_arr = [0x00, 0x07, 0x00, 0xCB, 0xF9, 0x90, 0xA4, 0xC6, 0x7C, 0xFB, 0x48, 0x85, 0x74, 0xAC, 0x98, 0x0C, 0x68, 0x39, 0xC1, 0xF7]
#	data_arr = [0x00, 0x07, 0x02]
#	data_arr = [0x00, 0x07, 0x85, 0x56, 0xCB, 0xCB, 0x6C, 0x7F, 0x64, 0x1E, 0x1F]
#	data = "".join([chr(i) for i in data_arr])
#	pds = PDS(data[1:])
#	print "pos %d" % (pds.pos)
#	print pds.getInt()
#	print "pos %d" % (pds.pos)
#	print pds.getInt()
#	print "pos %d" % (pds.pos)

	data = '\x00' * 100
	pds = PDS(data)
	pds.putInt(22222)
	pds.appendDataBlock('\x01\x02\x03')
	print pds._data
	print len(pds._data)
	pds.rewind()
	print pds.getInt()
	pds.rewind()
	print pds.getDataBlock(3)
