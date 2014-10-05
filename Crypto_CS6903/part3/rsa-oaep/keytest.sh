#!/bin/sh

#  run.sh
#  
#
#  Created by Dennis Mirante on 5/3/14.
#

echo "./hybridkeygen"
./hybridkeygen
echo "./gencertparams validityparameters.txt"
./gencertparams validityparameters.txt
echo "./keysign publickey.txt secretkey.txt validityparameters.txt > certificate.txt"
./keysign publickey.txt secretkey.txt validityparameters.txt > certificate.txt
echo "./keyverify publickey.txt certificate.txt validityparameters.txt"
./keyverify publickey.txt certificate.txt validityparameters.txt