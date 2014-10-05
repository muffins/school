################################################################################
## ascii2hex.py
## Author: Trevor Kroeger
## Date: 3/29/2014
## Lang: Python
## Description: Convert and ASCII File to a Hex file. The resulting file will
## contain only characters from 0 to 9 and A to F. Basically the ascii
## representation of hex.
################################################################################
ascii_file = open("paragraph.txt", "r");
pt = open("plaintext.txt", "w+");
fsize = 0;
for line in ascii_file:
  fsize = fsize + len(line);
num = str(fsize*2);
pt.write(num);
pt.write("\n");
ascii_file.seek(0);
for line in ascii_file:
  pt.write(line.encode('hex'));
