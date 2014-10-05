#!/usr/bin/python
import sys

def convert(fname):
	fin = open(fname, 'r')
	data = fin.read()
	l = fname.split('.')
	l.insert(-1,'hex')
	fout = open( '.'.join(l) , 'w')
	fout.write("%d\n" % (len(data)*2))
	for c in data:
		fout.write("%02X" % ord(c))
	fin.close()
	fout.close()

if __name__ == "__main__":
	if len(sys.argv) != 2:
		print "Usage: %s ascii_text.txt" % sys.argv[0]
		sys.exit()
	else:
		convert(sys.argv[1])
