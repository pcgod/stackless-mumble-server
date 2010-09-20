#!/bin/env python

import binascii
import cryptstate

rawkey = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
cs = cryptstate.CryptState()
#x.genKey()
cs.setKey(rawkey[0:16], rawkey[0:16], rawkey[0:16])
#a = "asdf"
#b = x.encrypt(rawkey)
#c = x.decrypt(b)

for i in range(300):
#for i in range(1000000):
	x = cs.encrypt(rawkey + rawkey + rawkey + rawkey + rawkey)
	y = cs.decrypt(x)
	print(binascii.hexlify(x))
	if y != False:
		print(binascii.hexlify(y))
	else:
		print("Decrypt error")
