#!/bin/bash

if [ $# -ne 1 ]
then
    echo "Usage: `basename $0` <Text Sample Prefix>"
    exit 85
fi

make clean
make
./keygen > key.txt
for i in $(ls $1*); do
    echo $i;
    ./encrypt key.txt $i > ciphertext.txt;
    ./decrypt key.txt ciphertext.txt > decryptedplaintext.txt;
    diff decryptedplaintext.txt $i;
done

