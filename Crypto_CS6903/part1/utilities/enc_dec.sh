#!/bin/bash

if [ $# -ne 1 ]
then
    echo "Usage: `basename $0` <Text Sample Prefix>"
    exit 85
fi

make clean
make
./keygen
for i in $(ls $1*); do
    echo $i;
    ./encrypt key.txt $i;
    ./decrypt key.txt ciphertext.txt;
    diff decryptedplaintext.txt $i;
done

