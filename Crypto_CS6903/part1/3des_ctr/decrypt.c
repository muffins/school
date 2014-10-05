/*
 * Nick Anderson
 * nanderson7@gmail.com
 * 03/27/2014
 *  
 * decrypt.c
 *
 * Program to decrypt a specified cipher text, given a 3DES key file.
 * This program makes use of the OpenSSL 3DES-ECB encryption function
 * in order to perform a Triple-DES CTR-Mode encryption scheme.
 *
 * This program expects the encrypted text input to be strictly hexadecimal
 * values.  That is, only A-F, 0-9 should be present in both the keyfile
 * and the ciphertext file to be decrypted.  Do NOT use prefix values such
 * as 0x for your hexidecimal values.
 */

#include <openssl/des.h>
#include <string.h>
#include <time.h>

#define MAX 4294967295
#define BLK_SIZE 8

int main(int argc, char* argv[]){
    // Local vars.
    size_t ret;
    unsigned char seed[64];
    unsigned char iv[BLK_SIZE];
    unsigned char enc_text[BLK_SIZE];
    unsigned char enc_key[BLK_SIZE];
    unsigned int ctr=0, num_bytes, key, val, i, j, iv_holder;
    int timed=0;
    clock_t start, stop;

    // File pointers
    FILE* keyfile;
    FILE* ciphertext;
    FILE* dplaintext;


    // Block Structs to hold each key
    DES_cblock key1;
    DES_key_schedule ks1;
    DES_cblock key2;
    DES_key_schedule ks2;
    DES_cblock key3;
    DES_key_schedule ks3;

    if(argc != 3 && argc != 4){
        printf("Usage: %s keyfile.txt ciphertext.txt [-t]\n", argv[0]);
        exit(1);
    }
    else if(argc == 4 && !strncmp(argv[3],"-t",2)){
        timed = 1;
    }

    // Open the plaintext file for reading
    ciphertext = fopen(argv[2], "r");
    if(ciphertext == NULL){
        fprintf(stderr, "Unable to open %s for reading!\n", argv[2]);
        exit(1);
    }

    // Read in the first value, supposed to be the length of the file.
    ret = fscanf(ciphertext, "%u", &num_bytes);
    if(ret != 1){
        fprintf(stderr, "Unable to read file size!\n");
        exit(1);
    }

    if(num_bytes % 2){
        fprintf(stderr, "Number of characters should be an even value.\n");
        fprintf(stderr, "There should be two characters to each byte!!\n");
        exit(1);
    }

    // The first number read in is the total number of hex symbols,
    // thus if we wish to get the number of bytes, we divide this value
    // by 2.  We first subtract off the 16 chars, or 8 bytes, of IV
    num_bytes = (num_bytes-16) / 2;

    // Verify the plaintext file is less than 4294967295 bytes
    if(num_bytes >  MAX){
        fprintf(stderr, "File is too large, Max file size is 536870911 Bytes!\n");
        exit(1);
    }

    // Open the keyfile for reading	
    keyfile = fopen("key.txt", "r");
    if(keyfile == NULL){
        fprintf(stderr, "Unable to open key.txt for reading\n");
        exit(1);
    }

    // Read key values from the file.
    // Key 1
    for(i=0; i<BLK_SIZE; i++){
        ret = fscanf(keyfile, "%02X", &key);
        if(ret != 1){
            fprintf(stderr, "Incorrect Key Length!\n");
            exit(1);
        }
        else{
            key1[i] = (unsigned char)key;
        }
    }
    // Key 2
    for(i=0; i<BLK_SIZE; i++){
        ret = fscanf(keyfile, "%02X", &key);
        if(ret != 1){
            fprintf(stderr, "Incorrect Key Length!\n");
            exit(1);
        }
        else{
            key2[i] = (unsigned char)key;
        }
    }
    // Key 3
    for(i=0; i<BLK_SIZE; i++){
        ret = fscanf(keyfile, "%02X", &key);
        if(ret != 1){
            fprintf(stderr, "Incorrect Key Length!\n");
            exit(1);
        }
        else{
            key3[i] = (unsigned char)key;
        }
    }

    // Set up the key schedules, checking that they are created correctly.
    // Key Schedule 1
    ret = DES_set_key((C_Block *)key1, &ks1);
    if(ret < 0){
        if(ret == -1){
            fprintf(stderr, "Key parity is incorrect!\n");
            exit(1);
        }
        else if(ret == -2){
            fprintf(stderr, "Key is too weak!\n");
            exit(1);
        }
        else{
            fprintf(stderr, "Error generating key schedule!\n");
            exit(1);
        }
    }

    // Key Schedule 2
    ret = DES_set_key((C_Block *)key2, &ks2);
    if(ret < 0){
        if(ret == -1){
            fprintf(stderr, "Key parity is incorrect!\n");
            exit(1);
        }
        else if(ret == -2){
            fprintf(stderr, "Key is too weak!\n");
            exit(1);
        }
        else{
            fprintf(stderr, "Error generating key schedule!\n");
            exit(1);
        }
    }

    // Key Schedule 3
    ret = DES_set_key((C_Block *)key3, &ks3);
    if(ret < 0){
        if(ret == -1){
            fprintf(stderr, "Key parity is incorrect!\n");
            exit(1);
        }
        else if(ret == -2){
            fprintf(stderr, "Key is too weak!\n");
            exit(1);
        }
        else{
            fprintf(stderr, "Error generating key schedule!\n");
            exit(1);
        }
    }

    // Read in the IV from the ciphertext
    for(i=0; i<BLK_SIZE; i++){
        ret = fscanf(ciphertext, "%02X", &iv_holder);
        if(ret != 1){
            fprintf(stderr, "Incorrect IV Length!\n");
            exit(1);
        }
        else{
            iv[i] = (unsigned char)iv_holder;
        }
    }

    // Init the counter to the value saved in the IV, commonly 0
    ctr += iv[4] << 24;
    ctr += iv[5] << 16;
    ctr += iv[6] << 8;
    ctr += iv[7];

    // Open the decryptedplaintext file for writing
    dplaintext = fopen("./decryptedplaintext.txt", "w");
    if(dplaintext == NULL){
        fprintf(stderr, "Unable to open decryptedplaintext.txt for writing!\n");
        exit(1);
    }

    // Write out the number of characters, not bytes.
    ret = fprintf(dplaintext, "%u\n", (num_bytes*2));
    if(ret <= 1){
        fprintf(stderr, "Writing byte size to decryptedplaintext.txt failed!\n");
        exit(1);
    }

    // Perform the decryption
    i = 0;
    if(timed)
        start = clock();
    while(fscanf(ciphertext, "%02X", &val) != EOF){
        if(i == BLK_SIZE){ // The buffer is full, perform the encryption

            // Setup the IV+CTR
            iv[4] = (ctr >> 24) & 0xFF;
            iv[5] = (ctr >> 16) & 0xFF;
            iv[6] = (ctr >> 8) & 0xFF;
            iv[7] = ctr & 0xFF;

            // Encrypt the IV+CTR
            DES_ecb3_encrypt((C_Block *)iv, (C_Block *)enc_key, &ks1, &ks2, &ks3, DES_ENCRYPT);
            
            // Encrypt/write out the data to the cipher text file
            for(j=0; j<8; j++){
                fprintf(dplaintext, "%02X", (enc_key[j] ^ enc_text[j]));
            }
            // Increment the counter
            ctr++;

            // Reset 'i' and the clear_text buffer
            i = 0;
            memset(enc_text,0x0,BLK_SIZE);
        }

        // Get a byte from the clear text
        enc_text[i] = (unsigned char)val;
        i++;
    }

    // Encrypt one final time, to account for the last block
    
    // Setup the IV+CTR
    iv[4] = (ctr >> 24) & 0xFF;
    iv[5] = (ctr >> 16) & 0xFF;
    iv[6] = (ctr >> 8) & 0xFF;
    iv[7] = ctr & 0xFF;

    // Encrypt the IV
    DES_ecb3_encrypt((C_Block *)iv, (C_Block *)enc_key, &ks1, &ks2, &ks3, DES_ENCRYPT);

    // XOR the data and write to disk.
    for(j=0; j<i; j++){
        fprintf(dplaintext, "%02X", (enc_key[j] ^ enc_text[j]));
    }

    // If we are timing the run, print out the seconds it took to decrypt
    if(timed){
        stop = clock();
        printf("Decryption took %f seconds\n", (double)(stop - start)/CLOCKS_PER_SEC);
    }

    // Close all files.
    fclose(keyfile);
    fclose(dplaintext);
    fclose(ciphertext);
    return 1;
}

