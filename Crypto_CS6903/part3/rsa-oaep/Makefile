CC=gcc


all: hybridkeygen hybridencrypt hybriddecrypt keysign keyverify gencertparams
	
hybridkeygen:
	$(CC) -g hybridkeygen.c -o hybridkeygen -lcrypto

hybridencrypt:
	$(CC) -g hybridencrypt.c -o hybridencrypt -lcrypto

hybriddecrypt:
	$(CC) -g hybriddecrypt.c -o hybriddecrypt -lcrypto

keysign:
	$(CC) -g keysign.c -o keysign -lcrypto

keyverify:
	$(CC) -g keyverify.c -o keyverify -lcrypto

gencertparams:
	$(CC) -g gencertparams.c -o gencertparams -lcrypto

clean:
	rm -rf hybridencrypt hybriddecrypt hybridkeygen ciphertext.txt secretkey.txt
	rm -rf gencertparams keysign keyverify decryptedplaintext.txt publickey.txt
	rm -rf validityparameters.txt
