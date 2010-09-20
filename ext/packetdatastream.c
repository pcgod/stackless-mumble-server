#define PY_SSIZE_T_CLEAN 1
#include <Python.h>

#include <stdint.h>

#define FALSE 0
#define TRUE 1

typedef struct {
	PyObject_HEAD
	unsigned char *data;
	uint32_t maxsize;
	uint32_t offset;
	uint32_t overshoot;
	int ok;
} PacketDataStreamObject;

staticforward PyTypeObject PacketDataStreamType;

static PyObject*
PacketDataStream_new(PyTypeObject* type, PyObject* args, PyObject* kwds)
{
	Py_buffer data;
	PacketDataStreamObject* self;

	if (!PyArg_ParseTuple(args, "s*", &data))
		return NULL;

	self = (PacketDataStreamObject*)type->tp_alloc(type, 0);

	self->data = (unsigned char*)malloc(data.len);
	memcpy(self->data, data.buf, data.len);
	self->maxsize = data.len;
	self->offset = self->overshoot = 0;
	self->ok = TRUE;

	PyBuffer_Release(&data);

	(void)kwds;
	return (PyObject*)self;
}

static void
PacketDataStream_dealloc(PacketDataStreamObject* self)
{
	free(self->data);
	self->ob_type->tp_free(self);
}

static PyObject*
PacketDataStream_size(PacketDataStreamObject* self)
{
	return Py_BuildValue("I", self->offset);
}

static PyObject*
PacketDataStream_capacity(PacketDataStreamObject* self)
{
	return Py_BuildValue("I", self->maxsize);
}

static PyObject*
PacketDataStream_isValid(PacketDataStreamObject* self)
{
	if (self->ok != FALSE)
		Py_RETURN_TRUE;

	Py_RETURN_FALSE;
}

inline static uint32_t
left(PacketDataStreamObject* self)
{
	return self->maxsize - self->offset;
}

static PyObject*
PacketDataStream_left(PacketDataStreamObject* self)
{
	return Py_BuildValue("I", left(self));
}

static PyObject*
PacketDataStream_undersize(PacketDataStreamObject* self)
{
	return Py_BuildValue("I", self->overshoot);
}

static PyObject*
PacketDataStream_rewind(PacketDataStreamObject* self)
{
	self->offset = 0;

	Py_RETURN_NONE;
}

static PyObject*
PacketDataStream_truncate(PacketDataStreamObject* self)
{
	self->maxsize = self->offset;

	Py_RETURN_NONE;
}

inline static uint64_t
next(PacketDataStreamObject* self) {
	uint64_t ret;

	if (self->offset < self->maxsize)
		ret = self->data[self->offset++];
	else {
		self->ok = FALSE;
		ret = 0;
	}

	return ret;
}

static PyObject*
PacketDataStream_next(PacketDataStreamObject* self)
{
	return Py_BuildValue("k", next(self));
}

static PyObject*
PacketDataStream_skip(PacketDataStreamObject* self, PyObject* args)
{
	uint32_t len;

	if (!PyArg_ParseTuple(args, "I", &len))
		return NULL;

	if (left(self) >= len)
		self->offset += len;
	else
		self->ok = FALSE;

	Py_RETURN_NONE;
}


inline static void
append(PacketDataStreamObject* self, uint64_t v)
{
	if (self->offset < self->maxsize)
		self->data[self->offset++] = (unsigned char)v;
	else {
		self->ok = FALSE;
		self->overshoot++;
	}
}

static PyObject*
PacketDataStream_append(PacketDataStreamObject* self, PyObject* args)
{
	uint32_t v;

	if (!PyArg_ParseTuple(args, "I", &v))
		return NULL;

	append(self, v);

	Py_RETURN_NONE;
}

static PyObject*
PacketDataStream_appendDataBlock(PacketDataStreamObject* self, PyObject* args)
{
	Py_buffer buffer;
	int l;

	if (!PyArg_ParseTuple(args, "s*", &buffer))
		return NULL;

	if (left(self) >= buffer.len) {
		memcpy(&self->data[self->offset], buffer.buf, buffer.len);
		self->offset += buffer.len;
	} else {
		l = left(self);
		memset(&self->data[self->offset], 0, l);
		self->offset += l;
		self->overshoot += buffer.len - l;
		self->ok = FALSE;
	}

	PyBuffer_Release(&buffer);
	Py_RETURN_NONE;
}

inline static uint64_t
getInt(PacketDataStreamObject* self)
{
	uint64_t i = 0;
	uint64_t v = next(self);

	if ((v & 0x80) == 0x00) {
		i = (v & 0x7F);
	} else if ((v & 0xC0) == 0x80) {
		i = (v & 0x3F) << 8 | next(self);
	} else if ((v & 0xF0) == 0xF0) {
		switch (v & 0xFC) {
		case 0xF0:
			i = next(self) << 24 | next(self) << 16 | next(self) << 8 | next(self);
			break;
		case 0xF4:
			i = next(self) << 56 | next(self) << 48 | next(self) << 40 | next(self) << 32 | next(self) << 24 | next(self) << 16 | next(self) << 8 | next(self);
			break;
		case 0xF8:
			i = getInt(self);
			i = ~i;
			break;
		case 0xFC:
			i = v & 0x03;
			i = ~i;
			break;
		default:
			self->ok = FALSE;
			i = 0;
			break;
		}
	} else if ((v & 0xF0) == 0xE0) {
		i = (v & 0x0F) << 24 | next(self) << 16 | next(self) << 8 | next(self);
	} else if ((v & 0xE0) == 0xC0) {
		i = (v & 0x1F) << 16 | next(self) << 8 | next(self);
	}

	return i;
}

static PyObject*
PacketDataStream_getInt(PacketDataStreamObject* self)
{
	return Py_BuildValue("k", getInt(self));
}

static PyObject*
PacketDataStream_putInt(PacketDataStreamObject* self, PyObject* args)
{
	uint64_t i;

	if (!PyArg_ParseTuple(args, "I", &i))
		return NULL;

	if ((i & 0x8000000000000000LL) && (~i < 0x100000000LL)) {
		// Signed number.
		i = ~i;
		if (i <= 0x3) {
			// Shortcase for -1 to -4
			append(self, 0xFC | i);
			Py_RETURN_NONE;
		} else {
			append(self, 0xF8);
		}
	}
	if (i < 0x80) {
		// Need top bit clear
		append(self, i);
	} else if (i < 0x4000) {
		// Need top two bits clear
		append(self, (i >> 8) | 0x80);
		append(self, i & 0xFF);
	} else if (i < 0x200000) {
		// Need top three bits clear
		append(self, (i >> 16) | 0xC0);
		append(self, (i >> 8) & 0xFF);
		append(self, i & 0xFF);
	} else if (i < 0x10000000) {
		// Need top four bits clear
		append(self, (i >> 24) | 0xE0);
		append(self, (i >> 16) & 0xFF);
		append(self, (i >> 8) & 0xFF);
		append(self, i & 0xFF);
	} else if (i < 0x100000000LL) {
		// It's a full 32-bit integer.
		append(self, 0xF0);
		append(self, (i >> 24) & 0xFF);
		append(self, (i >> 16) & 0xFF);
		append(self, (i >> 8) & 0xFF);
		append(self, i & 0xFF);
	} else {
		// It's a 64-bit value.
		append(self, 0xF4);
		append(self, (i >> 56) & 0xFF);
		append(self, (i >> 48) & 0xFF);
		append(self, (i >> 40) & 0xFF);
		append(self, (i >> 32) & 0xFF);
		append(self, (i >> 24) & 0xFF);
		append(self, (i >> 16) & 0xFF);
		append(self, (i >> 8) & 0xFF);
		append(self, i & 0xFF);
	}

	Py_RETURN_NONE;
}

static PyObject*
PacketDataStream_getDataBlock(PacketDataStreamObject* self, PyObject* args)
{
	uint32_t len;
	PyObject* ret;

	if (!PyArg_ParseTuple(args, "I", &len))
		return NULL;

	if (len <= left(self)) {
		ret = Py_BuildValue("s#", self->data + self->offset, len);
		self->offset += len;
	} else {
		self->ok = FALSE;
		Py_RETURN_NONE;
	}

	return ret;
}

static PyObject*
PacketDataStream_getData(PacketDataStreamObject* self)
{
	return Py_BuildValue("s#", self->data, self->maxsize);
}

static PyMethodDef PacketDataStreamObjectMethods[] = {
	{"size", (PyCFunction)PacketDataStream_size, METH_NOARGS, NULL},
	{"capacity", (PyCFunction)PacketDataStream_capacity, METH_NOARGS, NULL},
	{"isValid", (PyCFunction)PacketDataStream_isValid, METH_NOARGS, NULL},
	{"left", (PyCFunction)PacketDataStream_left, METH_NOARGS, NULL},
	{"undersize", (PyCFunction)PacketDataStream_undersize, METH_NOARGS, NULL},
	{"rewind", (PyCFunction)PacketDataStream_rewind, METH_NOARGS, NULL},
	{"truncate", (PyCFunction)PacketDataStream_truncate, METH_NOARGS, NULL},
	{"next", (PyCFunction)PacketDataStream_next, METH_NOARGS, NULL},
	{"skip", (PyCFunction)PacketDataStream_skip, METH_VARARGS, NULL},
	{"append", (PyCFunction)PacketDataStream_append, METH_VARARGS, NULL},
	{"appendDataBlock", (PyCFunction)PacketDataStream_appendDataBlock, METH_VARARGS, NULL},
	{"getInt", (PyCFunction)PacketDataStream_getInt, METH_NOARGS, NULL},
	{"putInt", (PyCFunction)PacketDataStream_putInt, METH_VARARGS, NULL},
	{"getDataBlock", (PyCFunction)PacketDataStream_getDataBlock, METH_VARARGS, NULL},
	{"getData", (PyCFunction)PacketDataStream_getData, METH_NOARGS, NULL},
	{NULL, NULL, 0, NULL}
};

static PyTypeObject PacketDataStreamType = {
	PyObject_HEAD_INIT(NULL)
	0,	/* ob_size */
	"pds.PacketDataStream",	/* tp_name */
	sizeof(PacketDataStreamObject),	/* tp_size */
	0,	/* tp_itemsize */
	(destructor)PacketDataStream_dealloc,	/* tp_dealloc */
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
	PacketDataStreamObjectMethods,	/* tp_methods */
	NULL,	/* tp_members */
	0,	/* tp_getset */
	0,	/* tp_base */
	0,	/* tp_dict */
	0,	/* tp_descr_get */
	0,	/* tp_descr_set */
	0,	/* tp_dictoffset */
	0,	/* tp_init */
	0,	/* tp_alloc */
	PacketDataStream_new,	/* tp_new */
	0,	/* tp_free */
	0,	/* tp_is_gc */
	NULL,	/* tp_bases */
	NULL,	/* tp_mro */
	NULL,	/* tp_cache */
	NULL,	/* tp_subclasses */
	NULL,	/* tp_weaklist */
	NULL	/* tp_del */
};

static PyMethodDef PacketDataStreamMethods[] = {
	{NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC
initpacketdatastream(void)
{
	PyObject* m;

	if (PyType_Ready(&PacketDataStreamType) < 0)
		return;

	m = Py_InitModule3("packetdatastream", PacketDataStreamMethods, NULL);
	if (m == NULL)
		return;

	Py_INCREF(&PacketDataStreamType);
	PyModule_AddObject(m, "PacketDataStream", (PyObject*)&PacketDataStreamType);
}
