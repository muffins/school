This directory contains all the files required to build and run the key signing and verification programs.

To make the programs enter:
make clean
make

An example shell is included to run the program.  Type ./keytest.sh
and the following programs will be invoked:

./signaturekeygen
./hybridkeygen
./gencertreq publickey.txt  csr.txt
./sign signsecretkey.txt csr.txt > certificate.txt
./verify signpublickey.txt certificate.txt csr.txt


signaturekeygen generates the public and private rsa keys for the certificate authority (signpublickey.txt and signsecretkey.txt)

hybridkeygen generates the public and private rsa keys for the certificate requester into publickey.txt and secretkey.xtx

gencert generates a certificate signing request file containing key holder information and public key

sign generates the X509 certificate for the reqeuster using the certificate authority’s secret key and the the information in the certificate signing request file.  The X509 certificate contains the requester’s information and public key.  It is RSA SAH256 Hash signed by the certificate authority using the CA’s private key.

verify verifies the X509 certificate using the certificate authority’s public key and the certificate signing request file.  It checks the signature on the certificate file, the certificate’s validity in terms of Not Before and Not After time, and that parameters contained in the certificate match those specified in the certificate signing request file (csr.txt)

