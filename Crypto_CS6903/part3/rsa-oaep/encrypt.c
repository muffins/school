/*
 * Nick Anderson, 04/29/2014
 *
 * encrypt.c
 *
 * AES CBC with SHA256 HMAC
 * Modern Cryptography Project Part 3
 * Description: This code preforms encryption using the AES CBC.
 * scheme. The data to be encrypted is input in a file of the following form:
 *         -Line 1: Number of characters of data in the file
 *         -Line 2: Data in hex representation (A is 41, B is 42, etc.)
 * The output from running encryption is of the following form:
 *         -Line 1: Number of characters of data in the file
 *         -Line 2: Initialization Vector in hex representation (A is 41, B is 42, etc.)
 *         -Line 3: Encrypted Data in hex representation(A is 41, B is 42, etc.)
 * During encryption the inccoming data is padded so that it alines with a 
 * block boundary, the data padding is not added to the number of characters
 * shown on line 1 of the ciphertext file.
 * Usage:
 *       ./encrypt <key_filename> <plaintext.hex_filename> [-t]
 * The use of -t will time the operation of the encryption, which does not
 * include the associated file IO for loading the key or the data. Note that
 * the time is always calculated the flag determines if the time is printed.
 * Key_filename and plaintext.hex_filename must be supplied to print the timeing
 * however if timing isn't desired then the default names for the key_filename
 * and plaintext.hex_filename are key.txt and plaintext.txt repectively
 * 
 * 
 * Enc’(k,m): compute a time-stamp ts,
 *            c1=Enc(k1,m),
 *            t=Tag(k2, c1|ts);
 *   finally, send (ts, c1, t)
 * 
 * SHA2 - 256 bit KEY
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>

// Globally defined sizes
#define SHA_KEY_SIZE 32

int main(int argc, char* argv[]){

  // Counter variables
  unsigned int f_size, pad;
  size_t inputslength;
  int i, j, ret, padding, timed=0;

  // Timing Variables
  struct timespec tstart={0,0}, tmid1={0,0}, tmid2={0,0}, tend={0,0};

  // Buffers for keys, encrypted text, plaintext, etc..
  char *key_name, *plaintext;
  unsigned int tstamp;
  unsigned char *enc_out=NULL;
  unsigned char *data_in=NULL;
  unsigned char *digest=NULL;
  unsigned char key_in[AES_BLOCK_SIZE];
  unsigned char iv_enc[AES_BLOCK_SIZE];
  unsigned char seed[SHA_KEY_SIZE*2]; // Seed the PRNG with 64 bytes of data.
  unsigned char sha_key[SHA_KEY_SIZE];

  // File pointers
  FILE *keyfile;
  FILE *urand;
  FILE *fout;
  FILE *fin;
  FILE *hmac;

  // AES Key Structure
  AES_KEY key;

  // Clear out the buffers, so our data is clean, except for seed, as it wont matter
  memset(key_in, 0x0, AES_BLOCK_SIZE);
  memset(sha_key, 0x0, SHA_KEY_SIZE);
  memset(iv_enc, 0x0, AES_BLOCK_SIZE);

  // Get the filenames from commandline
  if(argc != 1){
    if(argc != 3 && argc != 4){
      printf("Usage: %s keyfile.txt plaintext.txt [-t]\n", argv[0]);
      exit(-1);
    } else if(argc == 4 && !strncmp(argv[3],"-t",2)){
      timed = 1;
    }
    // Lets get our file names to some buffers
    key_name = argv[1];
    plaintext = argv[2];
  } else {
    // Using Default key and plaintext file names
    key_name = "key.txt";
    plaintext = "plaintext.txt";
  }

  // Load the Key from the key file
  keyfile = fopen(key_name,"r");
  if(keyfile == NULL){
    fprintf(stderr, "File '%s' needed to preform encryption - run keygen first\n",key_name);
    exit(-1);
  }
  for(i = 0; i < AES_BLOCK_SIZE; i++)
    fscanf(keyfile,"%02hhx",&key_in[i]);
  
  hmac = fopen("hmac_key.txt","w");
  if(hmac == NULL){
    fprintf(stderr, "Unable to open 'hmac_key.txt' for writing!\n");
    exit(-1);
  }

  // Open dev rand to seed our random data.
  urand = fopen("/dev/urandom","r");
  if(urand == NULL){
      fprintf(stderr, "Unable to open /dev/urandom for reading!\n");
      exit(-1);
  }

  // Read the rand data from /dev/urandom, 64 bytes worth of seed data.
  ret = fread(&seed, sizeof(char), SHA_KEY_SIZE*2, urand);
  if(ret < 8){
      fprintf(stderr, "Unable to obtain random seed from /dev/urandom!\n");
      exit(-1);
  }
  
  // Seed the PRNG with 64 bytes of random data.
  RAND_seed(&seed, SHA_KEY_SIZE*2);

  // Set the sha key with random byte data.
  if(!RAND_bytes(sha_key, SHA_KEY_SIZE)){
    fprintf(stderr, "Unable to obtain random bytes for SHA Key!\n");
    exit(-1);
  }

  // Set the AES Encryption Key to the Key that was imported from key.txt
  // int AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
  AES_set_encrypt_key(key_in, AES_BLOCK_SIZE*8, &key);
  
  // Open the file for the Ciphertext
  fout = fopen("ciphertext.txt","w+");
  if(fout == NULL){
    fprintf(stderr, "File 'ciphertext.txt' couldn't be opened or created... its your problem now\n");
    exit(-1);
  }

  // Set Initialization Vector
  if(!RAND_bytes(iv_enc, AES_BLOCK_SIZE)){
    fprintf(stderr, "Unable to obtain random bytes for Initialization Vector!\n");
    exit(-1);
  }

  // Load the Data for Encryption  
  fin = fopen(plaintext,"r");
  if(fin == NULL){
    fprintf(stderr, "File '%s' not found... Please provide clear text file to encrypt.\n",plaintext);
    exit(-1);
  }

  // Read in the filesize and Calulate the padding for the data.
  fscanf(fin,"%u\n",&f_size);
  if(f_size%2){
    fprintf(stderr, "File size should be divisble by 2! Exiting.\n");
    exit(-1);
  }
  f_size = f_size/2;
  pad = AES_BLOCK_SIZE - (f_size % AES_BLOCK_SIZE);
  
  // Allocate memory to store the clear text
  data_in = malloc(f_size+pad);
  memset(data_in, 0, (f_size+pad));
  if(data_in == NULL){
    fprintf(stderr, "Unable to allocate memory for reading!\n");
    exit(1);
  }

  // Read in the cleartext data.
  for(i = 0; i < f_size; i++){
    fscanf(fin, "%02hhx", &data_in[i]);
  }

  // Pad the cleartext data to make it alligned to a number divisible by AES_BLOCK_SIZE
  // We pad using data from the beginning of the buffer, for added randomness.
  for(i = 0; i < pad; i++)
    data_in[f_size+i] = data_in[i];
  
  // Print the size of the file to start of the cipher text file
  fprintf(fout, "%u\n", (f_size*2));

  // Print the initialization vector out to the cipher text file.
  for(i = 0; i < AES_BLOCK_SIZE; i++){
    fprintf(fout, "%02x", iv_enc[i]);
  }
  fprintf(fout, "\n");
  
  // Print the SHA256 Key to the hmac key file.
  for(i = 0; i < SHA_KEY_SIZE; i++)
    fprintf(hmac,"%02x",sha_key[i]);

  // Go get our super great timestamp
  tstamp = (unsigned)time(NULL);
  // Write the Time Stamp out to the file
  for(i = 0; i < 4; i++){
    unsigned char t = (tstamp >> (32 - (i+1)*8)) & 0xFF;
    fprintf(fout, "%02x", t);
  }
  fprintf(fout, "\n");

  // Encrypt the clear text data
  inputslength = f_size + pad;

  // Allocate memory to store the encrypted text, we add on one block size for the timestamp
  enc_out = malloc(inputslength + AES_BLOCK_SIZE);
  memset(enc_out, 0, (inputslength + AES_BLOCK_SIZE));
  if(enc_out == NULL){
    fprintf(stderr, "Unable to allocate memory for writing!\n");
    exit(-1);
  }

  // Start timing here
  if(timed)
    clock_gettime(CLOCK_MONOTONIC, &tstart);

  // Perform Encryption
  //void AES_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t length, 
  //                    const AES_KEY *key, unsigned char *ivec, const int enc);
  AES_cbc_encrypt(data_in, enc_out, inputslength, &key, iv_enc, AES_ENCRYPT);

  // Finish Timing Here
  if(timed)
    clock_gettime(CLOCK_MONOTONIC, &tmid1);

  // Write the Encrypted data to the ciphertext file
  for(i = 0; i < inputslength; i++)
    fprintf(fout,"%02x",enc_out[i]);
  fprintf(fout,"\n");
  
  // Begin timer for HMAC computation
  if(timed)
    clock_gettime(CLOCK_MONOTONIC, &tmid2);
  
  // append the time stamp to the encrypted data.
  for(i = 0; i < 4; i++){
    unsigned char t = (tstamp >> (32 - (i+1)*8)) & 0xFF;
    sprintf(&enc_out[inputslength + i], "%c", t);
  }

  // Compute the digest  
  digest = HMAC(EVP_sha256(), sha_key, SHA_KEY_SIZE, enc_out, (inputslength+AES_BLOCK_SIZE), NULL, NULL);

  if(digest == NULL){
    fprintf(stderr, "An error occured computing the message digest!\n");
    exit(-1);
  }

  if(timed)
    clock_gettime(CLOCK_MONOTONIC, &tend);
  
  // Write the message digest out to the file.
  for(i = 0; i < SHA_KEY_SIZE; i++)
    fprintf(fout, "%02x", digest[i]);
  
  //Print out timing information
  if(timed){
    printf("Encryption: %.10f s Tag: %.10f s Total: %.10f s\n",((double)tmid1.tv_sec + 1.0e-9*tmid1.tv_nsec) - ((double)tstart.tv_sec+ 1.0e-9*tstart.tv_nsec),
	                                                       ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) - ((double)tmid2.tv_sec+ 1.0e-9*tmid2.tv_nsec),
	                                                       (((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) - ((double)tmid2.tv_sec+ 1.0e-9*tmid2.tv_nsec))+(((double)tmid1.tv_sec + 1.0e-9*tmid1.tv_nsec) - ((double)tstart.tv_sec+ 1.0e-9*tstart.tv_nsec)));
  }

  // Close files
  fclose(keyfile);
  fclose(fin);
  fclose(fout);
  fclose(urand);
  fclose(hmac);

  // Free Heap allocated memory
  free(enc_out);
  free(data_in);

  // Finished Rummimg Encryption
  return 1;
}
