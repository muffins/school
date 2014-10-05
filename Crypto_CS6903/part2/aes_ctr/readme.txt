Programs within this directory are executed as specified in the project document. 

The project document also contains the analysis of various modes of HMAC tag
generation. 

Executing these programs with no parameters will cause text defining the usage to
be printed.  Ie.,

./keygen
./encrypt
./decrypt
./sign
./verify

To make the programs, do:
make clean
make

An example of how these program are used is provided in test.sh
To invoke it -  ./test.sh

Detailed information concerning how each program is invoked can be obtained by
running this script.  The script can be used for testing purposes by the grader.

