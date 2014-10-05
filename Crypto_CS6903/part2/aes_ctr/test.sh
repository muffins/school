#!/bin/bash

echo " "

echo "The following commands make the file:"
make clean
make
echo

echo "Generate the aes128 key for use by encrypt and decrypt:"
echo "./keygen aes128 > aes128key.txt"
./keygen aes128 > aes128key.txt

echo  " "
echo "aes128key.txt is:"
cat aes128key.txt
echo " "

echo "Generate the sha512 key for use by sign:"
echo "./keygen sha512 > sha512key.txt"
./keygen sha512 > sha512key.txt

echo  " "
echo "sha512key.txt is:"
cat sha512key.txt
echo " "

echo  " "
echo "Generate ciphertext.txt from plaintext.txt:"
echo "./encrypt aes128key.txt plaintext.txt > ciphertext.txt"
./encrypt aes128key.txt plaintext.txt > ciphertext.txt
echo " "

echo "plaintext.txt is:"
cat plaintext.txt
echo " "
echo " "

echo "ciphertext.txt is:"
cat ciphertext.txt
echo " "
echo " "

echo "sign the ciphertext file"
echo "./sign sha512key.txt sha512 ciphertext.txt signedciphertext.txt"
./sign sha512key.txt sha512 ciphertext.txt signedciphertext.txt
echo " "

t=$(date +"%s")

echo "signedciphertext.txt is:"
cat signedciphertext.txt
echo " "
echo " "

echo "At this point, we are assuming that signedciphertext.txt will be tranmitted"
echo "to and received by another party.  The receiver will then use the verify"
echo "program to verify that the file has not been compromised.  If verify finds"
echo "that the HMAC tag in the header of signedciphertext.txt does not agree with"
echo "the calculated HMAC tag, then TAG MISMATCH will be printed. signedciphertext.txt"
echo "has been compromised and should not be decrypted. If the timestamp in header"
echo "of signedciphertext.txt is not within 120 seconds of the current time, then"
echo "a replay of the message should be suspected and signedciphertext.txt should not"
echo "be decoded and used.  OK is printed if the current time does not exceed that in"
echo "the header of signedciphertext.txt and the calculated and received HMAC tag agree."
echo " "
echo " "
echo "You will be given the opportunity to wait 120 seconds to test that verify does"
echo "indeed reject the file if the current time exceeds the timestamp time by 120 seconds"
echo "If you chose to continue immediately, then the file should pass verification tests"
echo "and be decrypted.  If you chose to wait, then the file should be rejected and"
echo "decryption will be bypassed."
echo " "
echo "This shell will not allow you to inadervertently wait at the prompt and"
echo "allow clock time to continue to acrue to the point where verify will fail because you"
echo "waited to long to enter an n answer.  You have 100 seconds to answer the question."
echo "If you take longer than 100 seconds before finally answering the question with a n"
echo "answer, the program will terminate with an error message stating that you waited too"
echo "long to answer.  This 100 second time window should be enough to permit the grader"
echo "to edit the contents of signedciphertext.txt to induce an error that verify should"
echo "catch, if the grader choses to do so.  Waiting more than 100 seconds doesn't matter"
echo "in the case of a y answer, as we are waiting for at least 120 seconds to induce"
echo "failure"
echo " "
echo " "

chktime=1

while true; do
    read -p "Do you wish to test verify by exceeding the 120 sec time limit ?  (y or n)" yn
    case $yn in 
        [Yy]* ) echo "waiting...."; sleep 120# ; break;;
        [Nn]* ) chktime=0; break;;
        * ) echo "Please answer y or n";;
    esac
done

tnow=$(date +"%s")
tdiff=$((tnow - t))

if [ "$chktime" = 0 ]; then
    if [ $tdiff -gt 100 ]; then
        echo " "
        echo "You waited too long to answer the question - terminating"
        echo
        exit
    fi
fi

echo " "
echo "verify the file:"
echo "./verify sha512key.txt signedciphertext.txt unsignedciphertext.txt"
./verify sha512key.txt signedciphertext.txt unsignedciphertext.txt
echo " "

if [ "$chktime" =  0 ]; then
    echo "OK should have printed.  decrypt will be invoked to perform decryption."
    echo " "
    echo "./decrypt aes128key.txt unsignedciphertext.txt > plaintextprime.txt"
    ./decrypt aes128key.txt unsignedciphertext.txt > plaintextprime.txt

    echo " "
    echo "plaintextprime.txt is:"
    cat plaintextprime.txt
    echo " "
    echo " "
    echo "diff is now invoked to compare plaintextprime.txt to plaintext.txt"
    echo "No differences should be noted."
    echo " "
    echo "diff plaintextprime.txt plaintext.txt"
    diff plaintextprime.txt plaintext.txt
    echo " "
else
    echo "TIMESTAMP OUT OF TOLERANCE should ahve printed.  The shell will terminate."
    echo " "
fi
echo "Script execution complete."


