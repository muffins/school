
if [ $# -ne 1 ]
then
	echo "Usage: $0 <Plain Text Filename>"
	exit 1;
fi;

./hybridkeygen
./gencertparams validityparameters.txt
./keysign publickey.txt secretkey.txt validityparameters.txt > cert.txt
./keyverify publickey.txt cert.txt validityparameters.txt
./hybridencrypt publickey.txt $1
./hybriddecrypt publickey.txt secretkey.txt ciphertext.txt
diff decryptedplaintext.txt $1
