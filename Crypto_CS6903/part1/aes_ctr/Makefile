all:keygen encrypt decrypt
	
keygen:
	gcc keygen.c -o keygen -lcrypto

encrypt:
	gcc encrypt.c -o encrypt -lcrypto

decrypt:
	gcc decrypt.c -o decrypt -lcrypto

clean:
	rm -rf encrypt decrypt keygen
