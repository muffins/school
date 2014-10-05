/*
 * Nick Anderson
 * nanderson7@gmail.com
 * 03/27/2014
 *  
 * keygen.c
 * 
 * Key Generation program for a Triple DES in ctr-mode implementation.
 * Created for Modern Cryptography, Spring 2014
 *
 * This program writes out the Triple DES key in strictly HEX values,
 * that is the only characters written are A-F and 0-9, there are no
 * Hex prefixes.
 */

#include <openssl/des.h>
#include <openssl/rand.h>

    int main(int argc, char* argv[]){
    int i;
    size_t ret;
    char seed[64];

    // Create local variables for the 3 unique keys
    DES_cblock key1;
    DES_cblock key2;
    DES_cblock key3;

    FILE *urand;
    FILE *keyfile;
    keyfile = fopen("key.txt","w+");
    if(keyfile == NULL){
        fprintf(stderr, "Unable to open key.txt for writing!\n");
        exit(1);
    }

    urand = fopen("/dev/urandom","r");
    if(urand == NULL){
        fprintf(stderr, "Unable to open /dev/urandom for reading!\n");
        exit(1);
    }

    // Read the rand data from /dev/urandom
    ret = fread(&seed, 8, 8, urand);
    if(ret < 8){
        fprintf(stderr, "Unable to obtain random seed from /dev/urandom!\n");
        exit(1);
    }
    fclose(urand);

    // Seed the PRNG
    RAND_seed(&seed, 8);

    // Generate three unique keys to use for 3DES
    if(!DES_random_key(&key1)){
        fprintf(stderr, "PRNG was not seeded sufficiently!\n");
        exit(1);
    }
    if(!DES_random_key(&key2)){
        fprintf(stderr, "PRNG was not seeded sufficiently!\n");
        exit(1);
    }
    if(!DES_random_key(&key3)){
        fprintf(stderr, "PRNG was not seeded sufficiently!\n");
        exit(1);
    }

    // Write key 1 to the disk
    for(i=0; i < 8; i++){
        fprintf(keyfile, "%02x", key1[i]);
    }
    // Write key 2 to the disk
    for(i=0; i < 8; i++){
        fprintf(keyfile, "%02x", key2[i]);
    }
    // Write key 3 to the disk
    for(i=0; i < 8; i++){
        fprintf(keyfile, "%02x", key3[i]);
    }

    // Close the key file.
    fclose(keyfile);
    return 1;
}
