#define PY_SSIZE_T_CLEAN 1
#include <Python.h>

#include <openssl/aes.h>
#include <openssl/rand.h>
#include <stdint.h>

#define FALSE 0
#define TRUE 1

typedef struct {
	PyObject_HEAD
	unsigned char raw_key[AES_BLOCK_SIZE];
	unsigned char encrypt_iv[AES_BLOCK_SIZE];
	unsigned char decrypt_iv[AES_BLOCK_SIZE];
	unsigned char decrypt_history[0x100];

	unsigned int uiGood;
	unsigned int uiLate;
	unsigned int uiLost;
	unsigned int uiResync;

	unsigned int uiRemoteGood;
	unsigned int uiRemoteLate;
	unsigned int uiRemoteLost;
	unsigned int uiRemoteResync;

	AES_KEY encrypt_key;
	AES_KEY decrypt_key;
	int valid;
} CryptStateObject;

staticforward PyTypeObject CryptStateType;

static void ocb_encrypt(CryptStateObject* self, const unsigned char* plain, unsigned char* encrypted, unsigned int len, const unsigned char* nonce, unsigned char* tag);
static void ocb_decrypt(CryptStateObject* self, const unsigned char* encrypted, unsigned char* plain, unsigned int len, const unsigned char* nonce, unsigned char* tag);

static PyObject*
CryptState_new(PyTypeObject* type, PyObject* args, PyObject* kwds)
{
	int i;
	CryptStateObject* self;
	self = (CryptStateObject*)type->tp_alloc(type, 0);

	for (i = 0; i < 0x100; i++)
		self->decrypt_history[i] = 0;

	self->uiGood = self->uiLate = self->uiLost = self->uiResync = 0;
	self->uiRemoteGood = self->uiRemoteLate = self->uiRemoteLost = self->uiRemoteResync = 0;
	self->valid = FALSE;

	(void)args;
	(void)kwds;
	return (PyObject*)self;
}

static void
CryptState_dealloc(CryptStateObject* self)
{
	self->ob_type->tp_free(self);
}

static PyObject*
CryptState_isValid(CryptStateObject* self)
{
	if (self->valid != FALSE)
		Py_RETURN_TRUE;

	Py_RETURN_FALSE;
}

static PyObject*
CryptState_genKey(CryptStateObject* self)
{
	RAND_bytes(self->raw_key, AES_BLOCK_SIZE);
	RAND_bytes(self->encrypt_iv, AES_BLOCK_SIZE);
	RAND_bytes(self->decrypt_iv, AES_BLOCK_SIZE);
	AES_set_encrypt_key(self->raw_key, 128, &self->encrypt_key);
	AES_set_decrypt_key(self->raw_key, 128, &self->decrypt_key);
	self->valid = TRUE;

	Py_RETURN_NONE;
}

static PyObject*
CryptState_setKey(CryptStateObject* self, PyObject* args) {
	Py_buffer rkey, eiv, div;

	if (!PyArg_ParseTuple(args, "s*s*s*", &rkey, &eiv, &div))
		return NULL;

	if (rkey.len != AES_BLOCK_SIZE || eiv.len != AES_BLOCK_SIZE || div.len != AES_BLOCK_SIZE) {
		PyErr_SetString(PyExc_ValueError, "all parameters must have 16 characters");
		return NULL;
	}

	memcpy(self->raw_key, rkey.buf, AES_BLOCK_SIZE);
	memcpy(self->encrypt_iv, eiv.buf, AES_BLOCK_SIZE);
	memcpy(self->decrypt_iv, div.buf, AES_BLOCK_SIZE);
	AES_set_encrypt_key(self->raw_key, 128, &self->encrypt_key);
	AES_set_decrypt_key(self->raw_key, 128, &self->decrypt_key);
	self->valid = TRUE;

	PyBuffer_Release(&rkey);
	PyBuffer_Release(&eiv);
	PyBuffer_Release(&div);

	Py_RETURN_NONE;
}

static PyObject*
CryptState_setDecryptIV(CryptStateObject* self, PyObject* args)
{
	Py_buffer iv;

	if (!PyArg_ParseTuple(args, "s*", &iv))
		return NULL;

	if (iv.len != AES_BLOCK_SIZE) {
		PyErr_SetString(PyExc_ValueError, "parameter must have 16 characters");
		return NULL;
	}

	memcpy(self->decrypt_iv, iv.buf, AES_BLOCK_SIZE);

	PyBuffer_Release(&iv);

	Py_RETURN_NONE;
}

static PyObject*
CryptState_getEncryptIV(CryptStateObject* self)
{
	return Py_BuildValue("s#", self->encrypt_iv, AES_BLOCK_SIZE);
}

static PyObject*
CryptState_encrypt(CryptStateObject* self, PyObject* args)
{
	int i;
	unsigned char tag[AES_BLOCK_SIZE];
	Py_buffer source;
	unsigned char* dst;

	if (self->valid != TRUE) {
		PyErr_SetString(PyExc_TypeError, "object not initialized");
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "s*", &source))
		return NULL;

	dst = (unsigned char*)malloc(source.len + 4);

	// First, increase our IV.
	for (i = 0; i < AES_BLOCK_SIZE; i++)
		if (++self->encrypt_iv[i])
			break;

//	Py_BEGIN_ALLOW_THREADS
	ocb_encrypt(self, source.buf, dst + 4, source.len, self->encrypt_iv, tag);
//	Py_END_ALLOW_THREADS

	dst[0] = self->encrypt_iv[0];
	dst[1] = tag[0];
	dst[2] = tag[1];
	dst[3] = tag[2];

	PyObject* ret = Py_BuildValue("s#", dst, source.len + 4);
	free(dst);

	PyBuffer_Release(&source);

	return ret;
}

static PyObject*
CryptState_decrypt(CryptStateObject* self, PyObject* args)
{
	Py_buffer source;
	unsigned char* dst;
	int i;

	unsigned char saveiv[AES_BLOCK_SIZE];
	unsigned char ivbyte;
	int restore = 0;
	unsigned char tag[AES_BLOCK_SIZE];

	int lost = 0;
	int late = 0;

	if (self->valid != TRUE) {
		PyErr_SetString(PyExc_TypeError, "object not initialized");
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "s*", &source))
		return NULL;

	ivbyte = ((unsigned char*)source.buf)[0];

	memcpy(saveiv, self->decrypt_iv, AES_BLOCK_SIZE);

	if (((self->decrypt_iv[0] + 1) & 0xFF) == ivbyte) {
		// In order as expected.
		if (ivbyte > self->decrypt_iv[0]) {
			self->decrypt_iv[0] = ivbyte;
		} else if (ivbyte < self->decrypt_iv[0]) {
			self->decrypt_iv[0] = ivbyte;
			for (i = 1; i < AES_BLOCK_SIZE; i++)
				if (++self->decrypt_iv[i])
					break;
		} else {
			Py_RETURN_FALSE;
		}
	} else {
		// This is either out of order or a repeat.

		int diff = ivbyte - self->decrypt_iv[0];
		if (diff > 128)
			diff = diff - 256;
		else if (diff < -128)
			diff = diff + 256;

		if ((ivbyte < self->decrypt_iv[0]) && (diff > -30) && (diff < 0)) {
			// Late packet, but no wraparound.
			late = 1;
			lost = -1;
			self->decrypt_iv[0] = ivbyte;
			restore = 1;
		} else if ((ivbyte > self->decrypt_iv[0]) && (diff > -30) && (diff < 0)) {
			// Last was 0x02, here comes 0xff from last round
			late = 1;
			lost = -1;
			self->decrypt_iv[0] = ivbyte;
			for (i = 1; i < AES_BLOCK_SIZE; i++)
				if (self->decrypt_iv[i]--)
					break;
			restore = 1;
		} else if ((ivbyte > self->decrypt_iv[0]) && (diff > 0)) {
			// Lost a few packets, but beyond that we're good.
			lost = ivbyte - self->decrypt_iv[0] - 1;
			self->decrypt_iv[0] = ivbyte;
		} else if ((ivbyte < self->decrypt_iv[0]) && (diff > 0)) {
			// Lost a few packets, and wrapped around
			lost = 256 - self->decrypt_iv[0] + ivbyte - 1;
			self->decrypt_iv[0] = ivbyte;
			for (i = 1; i < AES_BLOCK_SIZE; i++)
				if (++self->decrypt_iv[i])
					break;
		} else {
			Py_RETURN_FALSE;
		}

		if (self->decrypt_history[self->decrypt_iv[0]] == self->decrypt_iv[1]) {
			memcpy(self->decrypt_iv, saveiv, AES_BLOCK_SIZE);
			Py_RETURN_FALSE;
		}
	}

	dst = (unsigned char*)malloc(source.len - 4);
//	Py_BEGIN_ALLOW_THREADS
	ocb_decrypt(self, ((unsigned char*)source.buf) + 4, dst, source.len - 4, self->decrypt_iv, tag);
//	Py_END_ALLOW_THREADS

	if (memcmp(tag, ((unsigned char*)source.buf) + 1, 3) != 0) {
		memcpy(self->decrypt_iv, saveiv, AES_BLOCK_SIZE);
		free(dst);
		Py_RETURN_FALSE;
	}
	self->decrypt_history[self->decrypt_iv[0]] = self->decrypt_iv[1];

	if (restore)
		memcpy(self->decrypt_iv, saveiv, AES_BLOCK_SIZE);

	self->uiGood++;
	self->uiLate += late;
	self->uiLost += lost;

	PyObject* ret = Py_BuildValue("s#", dst, source.len - 4);
	free(dst);

	PyBuffer_Release(&source);

	return ret;
}

static PyMethodDef CryptStateObjectMethods[] = {
	{"isValid", (PyCFunction)CryptState_isValid, METH_NOARGS, NULL},
	{"genKey", (PyCFunction)CryptState_genKey, METH_NOARGS, NULL},
	{"setKey", (PyCFunction)CryptState_setKey, METH_VARARGS, NULL},
	{"setDecryptIV", (PyCFunction)CryptState_setDecryptIV, METH_VARARGS, NULL},
	{"getEncryptIV", (PyCFunction)CryptState_getEncryptIV, METH_NOARGS, NULL},
	{"encrypt", (PyCFunction)CryptState_encrypt, METH_VARARGS, "Encrypts a string"},
	{"decrypt", (PyCFunction)CryptState_decrypt, METH_VARARGS, "Decrypts a string"},
	{NULL, NULL, 0, NULL}
};

static PyTypeObject CryptStateType = {
	PyObject_HEAD_INIT(NULL)
	0,	/* ob_size */
	"cryptstate.CryptState",	/* tp_name */
	sizeof(CryptStateObject),	/* tp_size */
	0,	/* tp_itemsize */
	(destructor)CryptState_dealloc,	/* tp_dealloc */
	0,	/* tp_print */
	0,	/* tp_getattr */
	0,	/* tp_setattr */
	0,	/* tp_compare */
	0,	/* tp_repr */
	0,	/* tp_as_number */
	0,	/* tp_as_sequence */
	0,	/* tp_as_mapping */
	0,	/* tp_hash */
	0,	/* tp_call */
	0,	/* tp_str */
	0,	/* tp_getattro */
	0,	/* tp_setattro */
	0,	/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT,	/* tp_flags */
	NULL,	/* tp_doc */
	0,	/* tp_traverse */
	0,	/* tp_clear */
	0,	/* tp_richcompare */
	0,	/* tp_weaklistoffset */
	0,	/* tp_iter */
	0,	/* tp_iternext */
	CryptStateObjectMethods,	/* tp_methods */
	NULL,	/* tp_members */
	0,	/* tp_getset */
	0,	/* tp_base */
	0,	/* tp_dict */
	0,	/* tp_descr_get */
	0,	/* tp_descr_set */
	0,	/* tp_dictoffset */
	0,	/* tp_init */
	0,	/* tp_alloc */
	CryptState_new,	/* tp_new */
};

static PyMethodDef CryptStateMethods[] = {
	{NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC
initcryptstate(void)
{
	PyObject* m;

	if (PyType_Ready(&CryptStateType) < 0)
		return;

	m = Py_InitModule3("cryptstate", CryptStateMethods, NULL);
	if (m == NULL)
		return;

	Py_INCREF(&CryptStateType);
	PyModule_AddObject(m, "CryptState", (PyObject*)&CryptStateType);
}

#if defined(__LP64__)

#define BLOCKSIZE 2
#define SHIFTBITS 63
typedef uint64_t subblock;

#ifdef __x86_64__
static inline uint64_t SWAP64(register uint64_t __in) { register uint64_t __out; __asm__("bswap %q0" : "=r"(__out) : "0"(__in)); return __out; }
#else
#define SWAP64(x) ((static_cast<uint64_t>(x) << 56) | \
					((static_cast<uint64_t>(x) << 40) & 0xff000000000000ULL) | \
					((static_cast<uint64_t>(x) << 24) & 0xff0000000000ULL) | \
					((static_cast<uint64_t>(x) << 8)  & 0xff00000000ULL) | \
					((static_cast<uint64_t>(x) >> 8)  & 0xff000000ULL) | \
					((static_cast<uint64_t>(x) >> 24) & 0xff0000ULL) | \
					((static_cast<uint64_t>(x) >> 40) & 0xff00ULL) | \
					((static_cast<uint64_t>(x)  >> 56)))
#endif

#define SWAPPED(x) SWAP64(x)

#else
#define BLOCKSIZE 4
#define SHIFTBITS 31
typedef uint32_t subblock;
#define SWAPPED(x) __builtin_bswap32(x)
#endif

typedef subblock keyblock[BLOCKSIZE];

#define HIGHBIT (1<<SHIFTBITS);

inline static void
XOR(subblock* dst, const subblock* a, const subblock* b)
{
	int i;
	for (i = 0; i < BLOCKSIZE; i++)
		dst[i] = a[i] ^ b[i];
}

inline static void
S2(subblock* block)
{
	int i;
	subblock carry = SWAPPED(block[0]) >> SHIFTBITS;
	for (i = 0; i < BLOCKSIZE - 1; i++)
		block[i] = SWAPPED((SWAPPED(block[i]) << 1) | (SWAPPED(block[i + 1]) >> SHIFTBITS));
	block[BLOCKSIZE - 1] = SWAPPED((SWAPPED(block[BLOCKSIZE - 1]) << 1) ^(carry * 0x87));
}

inline static void
S3(subblock* block)
{
	int i;
	subblock carry = SWAPPED(block[0]) >> SHIFTBITS;
	for (i = 0; i < BLOCKSIZE - 1; i++)
		block[i] ^= SWAPPED((SWAPPED(block[i]) << 1) | (SWAPPED(block[i + 1]) >> SHIFTBITS));
	block[BLOCKSIZE - 1] ^= SWAPPED((SWAPPED(block[BLOCKSIZE - 1]) << 1) ^(carry * 0x87));
}

inline static void
ZERO(subblock* block)
{
	int i;
	for (i = 0; i < BLOCKSIZE; i++)
		block[i] = 0;
}

#define AESencrypt(src,dst,key) AES_encrypt((const unsigned char *)src, (unsigned char *)dst, key);
#define AESdecrypt(src,dst,key) AES_decrypt((const unsigned char *)src, (unsigned char *)dst, key);

inline static void
ocb_encrypt(CryptStateObject* self, const unsigned char* plain, unsigned char* encrypted, unsigned int len, const unsigned char* nonce, unsigned char* tag)
{
	keyblock checksum, delta, tmp, pad;

	// Initialize
	AESencrypt(nonce, delta, &self->encrypt_key);
	ZERO(checksum);

	while (len > AES_BLOCK_SIZE) {
		S2(delta);
		XOR(tmp, delta, (const subblock *)plain);
		AESencrypt(tmp, tmp, &self->encrypt_key);
		XOR((subblock *)encrypted, delta, tmp);
		XOR(checksum, checksum, (const subblock *)plain);
		len -= AES_BLOCK_SIZE;
		plain += AES_BLOCK_SIZE;
		encrypted += AES_BLOCK_SIZE;
	}

	S2(delta);
	ZERO(tmp);
	tmp[BLOCKSIZE - 1] = SWAPPED(len * 8);
	XOR(tmp, tmp, delta);
	AESencrypt(tmp, pad, &self->encrypt_key);
	memcpy(tmp, plain, len);
	memcpy(((unsigned char *)tmp) + len, ((const unsigned char *)pad) + len, AES_BLOCK_SIZE - len);
	XOR(checksum, checksum, tmp);
	XOR(tmp, pad, tmp);
	memcpy(encrypted, tmp, len);

	S3(delta);
	XOR(tmp, delta, checksum);
	AESencrypt(tmp, tag, &self->encrypt_key);
}

inline static void
ocb_decrypt(CryptStateObject* self, const unsigned char* encrypted, unsigned char* plain, unsigned int len, const unsigned char* nonce, unsigned char* tag)
{
	keyblock checksum, delta, tmp, pad;

	// Initialize
	AESencrypt(nonce, delta, &self->encrypt_key);
	ZERO(checksum);

	while (len > AES_BLOCK_SIZE) {
		S2(delta);
		XOR(tmp, delta, (const subblock *)encrypted);
		AESdecrypt(tmp, tmp, &self->decrypt_key);
		XOR((subblock *)plain, delta, tmp);
		XOR(checksum, checksum, (const subblock *)plain);
		len -= AES_BLOCK_SIZE;
		plain += AES_BLOCK_SIZE;
		encrypted += AES_BLOCK_SIZE;
	}

	S2(delta);
	ZERO(tmp);
	tmp[BLOCKSIZE - 1] = SWAPPED(len * 8);
	XOR(tmp, tmp, delta);
	AESencrypt(tmp, pad, &self->encrypt_key);
	memset(tmp, 0, AES_BLOCK_SIZE);
	memcpy(tmp, encrypted, len);
	XOR(tmp, tmp, pad);
	XOR(checksum, checksum, tmp);
	memcpy(plain, tmp, len);

	S3(delta);
	XOR(tmp, delta, checksum);
	AESencrypt(tmp, tag, &self->encrypt_key);
}
