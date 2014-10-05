################################################################################
## hex2ascii.py
## Author: Trevor Kroeger
## Date: 3/29/2014
## Lang: Python
## Description: Convert a Hex File to an ASCII file.
################################################################################
import binascii;

ascii_file = open("decryptedplaintext.txt", "r");
pt = open("paragraph_out.txt", "w+");
val = 0;
val = int(ascii_file.readline());
for line in ascii_file:
  pt.write(binascii.unhexlify(line));