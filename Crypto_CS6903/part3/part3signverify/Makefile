all:gencertreq sign verify hybridkeygen signaturekeygen
	
gencertreq:
	gcc gencertreq.c -o gencertreq -lcrypto

sign:
	gcc sign.c -o sign -lcrypto

verify:
	gcc verify.c -o verify -lcrypto

hybridkeygen:
	gcc hybridkeygen.c -o hybridkeygen -lcrypto

signaturekeygen:
	gcc signaturekeygen.c -o signaturekeygen -lcrypto

clean:
	rm -rf gencertreq sign verify hybridkeygen signaturekeygen

