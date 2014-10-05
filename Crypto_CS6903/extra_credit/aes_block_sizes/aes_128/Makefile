all:keygen encrypt decrypt
	
keygen:
	gcc keygen.c -o keygen

encrypt:
	gcc encrypt.c -o encrypt -lssl -lcrypto -lrt

decrypt:
	gcc decrypt.c -o decrypt -lssl -lcrypto -lrt

clean:
	rm -rf encrypt decrypt keygen ciphertext.txt key.txt decryptedplaintext.txt
