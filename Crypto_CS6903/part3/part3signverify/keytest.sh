#!/bin/sh

#  run.sh
#  
#
#  Created by Dennis Mirante on 5/3/14.
#

echo "./signaturekeygen"
./signaturekeygen
echo "./hybridkeygen"
./hybridkeygen
echo "./gencertreq publickey.txt  csr.txt"
./gencertreq publickey.txt  csr.txt
echo "./sign signsecretkey.txt csr.txt > certificate.txt"
./sign signsecretkey.txt csr.txt > certificate.txt
echo "./verify signpublickey.txt certificate.txt csr.txt"
./verify signpublickey.txt certificate.txt csr.txt