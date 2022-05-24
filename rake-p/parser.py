import binascii

def parse_port(buffer):
	''' Gets the port from buffer
	
	 Params;
	 - buffer: the buffer
	
	 Return:
	 - the port
	'''
	return buffer.strip().split()[-1]

def parse_hosts(buffer):
	'''
	 Gets hosts from buffer
	
	 Params;
	  - buffer: the buffer
	'''
	return buffer.strip().split()[2:]


"""
Three functions below convert text/ints to bytes and vice versa
source: https://stackoverflow.com/a/7397689/13316992
"""
def text_to_bits(text, encoding='utf-8', errors='surrogatepass'):
	bits = bin(int(binascii.hexlify(text.encode(encoding, errors)), 16))[2:]
	return bits.zfill(8 * ((len(bits) + 7) // 8))

def text_from_bits(bits, encoding='utf-8', errors='surrogatepass'):
	n = int(bits, 2)
	return int2bytes(n).decode(encoding, errors)

def int2bytes(i):
	hex_string = '%x' % i
	n = len(hex_string)
	return binascii.unhexlify(hex_string.zfill(n + (n & 1)))

