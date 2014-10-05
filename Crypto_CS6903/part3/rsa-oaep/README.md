
##RSA-OAEP Asymmetric Encryption Scheme


###Running Instructions
To compile and run the code, you should be able to run the following
commands

```bash
	user@ubuntu:~/$ make
	user@ubuntu:~/$ ./run.sh plaintext.txt
```

This will compile all of the code, and run the encryption scheme using the
plaingtext.txt file as the file to encrypt.  Change the name of plaintext.txt
to the name of the file you wish to encrypt, but note that the file passed
to this scheme must conform to the cleartext file format specifications as follows

Line 1 of file must be a single unsigned integer, indicating the *number of characters*
which exist in the file
Line 2+ must be strictly Hexadecimal characters, representing the cleartext data
of the file contents.

To convert a normal plaint text file into the above text format, a python script
`ascii_to_hex.py` has been provided.  Simply run this file with the name of the
plain text file as the command argument, and it will convert the plain text
file into the needed format to run with the encryption scheme.




