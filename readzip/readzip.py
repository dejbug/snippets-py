import struct


class bytes_t(object):

	def __init__(self, string):
		self.bytes = struct.unpack("<%dB" % len(string), string)
		self.value = self.bytes_to_value(self.bytes)

	@staticmethod
	def bytes_to_value(bb):
		assert len(bb) >= 1 and len(bb) <= 8
		val = 0
		fac = 1
		for b in bb:
			val += fac * b
			fac = fac << 8
		return val

	def to_hex_str(self):
		return " ".join(map(lambda b: "%02X" % b, self.bytes))

	def to_dec(self):
		return self.value

	def to_bin(self):
		return "{0:>08s}".format(bin(self.value)[2:])

	def to_time(self):
		d = self.value
		S = (d & 0x1f) << 1
		M = (d >> 5) & 0x3f
		H = (d >> 11) & 0x1f
		return "%02d:%02d:%02d" % (H, M, S, )

	def to_date(self):
		d = self.value
		D = (d & 0x1f)
		M = (d >> 5) & 0xf
		Y = ((d >> 9) & 0x7f) + 1980
		return "%4d-%02d-%02d" % (Y, M, D, )


def str_to_hex_str(text):
	return " ".join("%02X" % ord(c) for c in text)


def dec_to_hex_str(val):
	return " ".join(map(lambda c: "%02X" % ord(c), struct.pack("I", sig)))


NOP		= 0
PUSH	= 0b000000001
PUSH_D	= 0b000000010
HEX		= 0b000000100
BIN		= 0b000001000
DEC		= 0b000010000
STR		= 0b000100000
BYTES	= 0b001000000
TIME	= 0b010000000
DATE	= 0b100000000


ncc_lochdr = (
	# ("signature", 4, HEX),
	("version", 2, DEC),
	("flags", 2, BIN),
	("compression", 2, DEC),
	("mod time", 2, TIME),
	("mod date", 2, DATE),
	("crc-32", 4, HEX),
	("c size", 4, DEC | PUSH_D),
	("u size", 4, DEC),
	("fname length", 2, DEC | PUSH_D),
	("ex field len", 2, DEC | PUSH_D),
	("fname", -2, STR),
	("ex field", -1, BYTES),
	("fdata", -1, BYTES),
)


ncc_cd = (
	# ("signature", 4, HEX),
	("version", 1, DEC),
	("machine", 1, DEC),
	("ver needed", 2, DEC),
	("flags", 2, BIN),
	("compression", 2, DEC),
	("mod time", 2, TIME),
	("mod date", 2, DATE),
	("crc-32", 4, HEX),
	("c size", 4, DEC | PUSH_D),
	("u size", 4, DEC),
	("fname length", 2, DEC | PUSH_D),
	("ex field len", 2, DEC | PUSH_D),
	("fcomm length", 2, DEC | PUSH_D),
	("disk # start", 2, DEC),
	("internal attr", 2, BIN),
	("external attr", 4, BIN),
	("offset l-hdr", 4, HEX),
	("fname", -3, STR),
	("ex field", -2, BYTES),
	("fcomm", -1, BYTES),

)


ncc_cdend = (
	# ("signature", 4, HEX),
	("disk # this", 2, DEC),
	("disk # start", 2, DEC),
	("entries this", 2, DEC),
	("entries all", 2, DEC),
	("cd size", 4, DEC),
	("offset cd", 4, DEC),
	("dcomm length", 2, DEC | PUSH_D),
	("dcomm", -1, STR),
)


nid_map = {0x02014b50:(ncc_cd, "Central Directory"), 0x04034b50:(ncc_lochdr, "Local Header"), 0x06054b50:(ncc_cdend, "Central Directory End"),}


def read_signature(zip, index):
	bb = zip.read(4)
	if not bb: return index, None
	elif len(bb) == 4: return index+4, bytes_t(bb).to_dec()
	raise Exception("unexpected EOF at %d" % index+len(bb))


def ncc_from_signature(sig):
	try: return nid_map[sig]
	except: pass
	raise Exception("unknown signature")


def run_ncc(ncc, zip, index=0):
	stack = []
	for n,c,f in ncc:
		ok, index_next, text = ncc_step(zip, stack, n, c, f, index)
		if ok: print_line(index, n, text)
		index = index_next
	return index


def ncc_step(zip, stack, n, c, f, index=0):

	if c == 0: return (False, index, None)
	elif c < 0: c = stack.pop(c)

	index += c

	if not f:
		return (False, index, None)

	elif f & STR:
		return (True, index, "[%d] '%s'" % (c, zip.read(c)))

	elif f & BYTES:
		return (True, index, ("[%d] " % c) + str_to_hex_str(zip.read(c)))

	else:
		bytes = bytes_t(zip.read(c))

		if f & PUSH: stack.append(bytes)
		elif f & PUSH_D: stack.append(bytes.to_dec())

		text = ""
		if f & HEX: text += bytes.to_hex_str()
		if f & BIN: text += "<%s>" % bytes.to_bin()
		if f & DEC: text += "(%s)" % bytes.to_dec()
		if f & TIME: text += bytes.to_time()
		if f & DATE: text += bytes.to_date()

		return (True, index, text)

	raise Exception("unexpected")


def print_line(index, n, text):
	if n == "signature": print
	print "%8X  %16s :" % (index, n,), text


if "__main__" == __name__:
	# with open("empty.zip", "rb") as zip:
	with open("two.zip", "rb") as zip:
		index, sig = read_signature(zip, 0)
		while sig:
			# print dec_to_hex_str(sig)
			ncc, name = ncc_from_signature(sig)
			print "\n", name, ":\n"
			index = run_ncc(ncc, zip, index)
			index, sig = read_signature(zip, index)
