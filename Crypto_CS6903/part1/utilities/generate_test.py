#!/usr/bin/python
import sys,random

def generate(num):
	random.seed()
	fname = "test_%d.txt" % num
	fout  = open(fname, "w")
	for i in xrange(num*1000):
		fout.write("%d" % random.randrange(0,10))
	fout.close()

if __name__ == "__main__":
	if len(sys.argv) != 2:
		print "Usage: %s <Size of File>" % sys.argv[0]
		sys.exit()
	else:
		generate(int(sys.argv[1]))