all:keygen encrypt decrypt sign verify
	
keygen:
	gcc keygen.c attr.c -o keygen -lcrypto

encrypt:
	gcc encrypt.c -o encrypt -lcrypto

decrypt:
	gcc decrypt.c -o decrypt -lcrypto
    
sign:
	gcc sign.c attr.c -o sign -lcrypto

verify:
	gcc verify.c attr.c -o verify -lcrypto    

clean:
	rm -rf encrypt decrypt keygen sign verify

