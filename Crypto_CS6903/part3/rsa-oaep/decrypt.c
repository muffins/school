////////////////////////////////////////////////////////////////////////////////
// AES CBC Decryption
// Modern Cryptography Project Part 2
// Description: This code preforms decryption using the AES CBC.
// scheme. The data to be decrypted is input in a file of the following form:
//         -Line 1: Number of characters of data in the file
//         -Line 2: Initial Value in hex representation (A is 41, B is 42, etc.)
//         -Line 3: Encrypted Data in hex representation(A is 41, B is 42, etc.)
// The output from running decryption is of the following form:
//         -Line 1: Number of characters of data in the file
//         -Line 2: Data in hex representation (A is 41, B is 42, etc.)
// During encryption the incoming data was padded so that it alines with a 
// block boundary, the data padding is not added to the number of characters
// shown on line 1 of the ciphertext file.
// Usage:
//       ./decrypt <key_filename> <ciphertext_filename> [-t]
// The use of -t will time the operation of the encryption, which does not
// include the associated file IO for loading the key initial value or the data.
// Note that the time is always calculated the flag determines if the time is
// printed. Key_filename and plaintext.hex_filename must be supplied to print
// the timing however if timing isn't desired then the default names for the
// key_filename and plaintext.hex_filename are key.txt and plaintext.txt
// repectively.
////////////////////////////////////////////////////////////////////////////////
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>

// Globally defined sizes
#define REPLAY_THRESH 120
#define SHA_KEY_SIZE 32

int main(int argc, char* argv[]){

  // Counter and Timing variables.
  int i,j,timed = 0;
  size_t inputslength;
  unsigned int f_size, pad, sha_padding, tstamp_o=0, tstamp_n=0;

  // Create Timing Variables
  struct timespec tstart={0,0}, tmid1={0,0}, tmid2={0,0}, tend={0,0};



  // Create Variables for holding the key_filename and ciphertext_filename
  char *key_name=NULL;
  char *ciphertext=NULL;
  unsigned char tmp=0x0;
  unsigned char key_in[AES_BLOCK_SIZE];
  unsigned char iv_dec[AES_BLOCK_SIZE];
  unsigned char sha_key[SHA_KEY_SIZE];
  unsigned char sha_o[SHA_KEY_SIZE];
  unsigned char tstamp_buff[4];
  unsigned char *sha_n=NULL;
  unsigned char *dec_out=NULL;
  unsigned char *data_in=NULL;

  // File Pointers
  FILE *keyfile;
  FILE *fout;
  FILE *hmac;
  FILE *fin;

  // AES Key Structure
  AES_KEY key;

  // Load the command line arguments
  if(argc != 1){
    if(argc != 3 && argc != 4){
      printf("Usage: %s keyfile.txt ciphertext.txt [-t]\n", argv[0]);
      exit(1);
    } else if(argc == 4 && !strncmp(argv[3],"-t",2)){
      timed = 1;
    }
    // Lets get our file names to some buffers
    key_name = argv[1];
    ciphertext = argv[2];
  } else {
    // Using Default key and ciphertext file names
    key_name = "key.txt";
    ciphertext = "ciphertext.txt";
  }

  // Load the Key from the key file
  keyfile = fopen(key_name,"r");
  if(keyfile == NULL){
    fprintf(stderr, "File '%s' needed to preform encryption - run keygen first\n",key_name);
    exit(1);
  }

  for(i = 0; i < AES_BLOCK_SIZE; i++)
    fscanf(keyfile,"%02hhx",&key_in[i]);

  // Set the AES Decryption Key to the Key that was imported from key.txt
  //int AES_set_decrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
  AES_set_decrypt_key(key_in, AES_BLOCK_SIZE*8, &key);

  // Open the Ciphertext file
  fin = fopen(ciphertext,"r");
  if(fin == NULL){
    fprintf(stderr, "File '%s' not found... Please provide data to encrypt.\n",ciphertext);
    exit(1);
  }

  // Load FileSize
  fscanf(fin,"%i\n",&f_size);
  
  // Load Initialization Vector
  for(i=0;i<AES_BLOCK_SIZE;i++){
    fscanf(fin,"%02hhx",&iv_dec[i]);
  }
  fscanf(fin,"%c",&tmp); // Here we grab the line between the IV and the sha_key
  
  hmac = fopen("hmac_key.txt","r");
  if(hmac == NULL){
    fprintf(stderr, "File '%s' needed to preform encryption - run keygen first\n",key_name);
    exit(1);
  }

  // Load the SHA256 Key
  for(i = 0; i < SHA_KEY_SIZE; i++)
    fscanf(hmac,"%02hhx",&sha_key[i]);

  /* Grab the timestamp from the cipher text file.  This should exist on Line 4 */
  for(i = 0; i < 4; i++){
    fscanf(fin, "%02hhx", &tmp); // NOTE THE FUCKING 'hh' VALUE ASS!  BUFFER OVERFLOWS OMG LOL!
    tstamp_buff[i] = tmp; // We'll need the buffer of the timestamp to recompute the MAC
    tstamp_o += ((unsigned int)tmp << (32-(i+1)*8));
  }

  //  Check for potential replay attacks.
  tstamp_n = (unsigned)time(NULL);

  if((tstamp_n - tstamp_o) > REPLAY_THRESH){
    fprintf(stderr, "Replay Attack Detected.  Exiting.\n");
    exit(-1);
  }

  // Calculate the PAD used on the data and load the data.
  f_size = f_size/2;
  pad = AES_BLOCK_SIZE - (f_size % AES_BLOCK_SIZE);
  sha_padding = SHA_KEY_SIZE - ((f_size + pad) % SHA_KEY_SIZE);
  
  // Allocate memory to store the cipher text
  //data_in = malloc(f_size + pad + sha_padding);
  data_in = malloc(f_size + pad + AES_BLOCK_SIZE);
  memset(data_in,0,(f_size + pad + AES_BLOCK_SIZE));
  if(data_in == NULL){
    fprintf(stderr, "Unable to allocate memory for writing!\n");
    exit(1);
  }

  // Load the ciphertext data
  for(i = 0; i < (f_size + pad); i++)
    fscanf(fin,"%02hhx",&data_in[i]);
  fscanf(fin,"%c",&tmp); // Here we grab the line between the SHA_Key and the timestamp

  // Load the MAC from the file
  for(i = 0; i < SHA_KEY_SIZE; i++)
    fscanf(fin,"%02hhx",&sha_o[i]);

  // append the time stamp to the encrypted data.
  for(i = 0; i < 4; i++)
    sprintf(&data_in[f_size + pad + i], "%c", tstamp_buff[i]);

  //Start Timing
  if(timed)
    clock_gettime(CLOCK_MONOTONIC, &tstart);

  sha_n = HMAC(EVP_sha256(), sha_key, SHA_KEY_SIZE, data_in, (f_size + pad + AES_BLOCK_SIZE), NULL, NULL);

  if(sha_n == NULL){
    fprintf(stderr, "An error occured computing the message digest!\n");
    exit(-1);
  }
  
  // Get Mid 1 time
  if(timed)
    clock_gettime(CLOCK_MONOTONIC, &tmid1);

  // Print an error if the data in the MACs doesn't match
  for(i = 0; i < SHA_KEY_SIZE; i++){
    if(sha_n[i] != sha_o[i]){
      printf("Error - The MAC doesn't match, maybe for Karate Lessons\n");
      exit(1);
    }
  }

  // Get Mid 2 time
  if(timed)
    clock_gettime(CLOCK_MONOTONIC, &tmid2);

  // Decrypt the Data
  //void AES_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t length, 
  //                    const AES_KEY *key, unsigned char *ivec, const int enc);
  inputslength = f_size + pad;

  // Allocate memory to store the clear text
  dec_out = malloc(f_size + pad);
  if(dec_out == NULL){
    fprintf(stderr, "Unable to allocate memory for writing!\n");
    exit(1);
  }

  // Perform Decryption
  AES_cbc_encrypt(data_in, dec_out, inputslength, &key, iv_dec, AES_DECRYPT);

  // Finish Timing Here
  if(timed)
    clock_gettime(CLOCK_MONOTONIC, &tend);

  // Write the Decrypted data to the Decrypted data file
  fout = fopen("decryptedplaintext.txt","w+");
  if(fout == NULL){
    fprintf(stderr, "File 'decryptedplaintext.txt' couldn't be opened or created... its your problem now\n");
    exit(1);
  }

  // Print the size of the file to start of the decoded plaintext file
  fprintf(fout,"%u\n",(f_size*2));
  for(i = 0; i < f_size; i++){
    fprintf(fout,"%02x",dec_out[i]);
  }
  
  //Print out timing information
  if(timed){
    printf("Decryption: %.10f s Tag Verify: %.10f s Tag: %.10f s Total: %.10f s\n",
      ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) - ((double)tmid2.tv_sec+ 1.0e-9*tmid2.tv_nsec),
	    ((double)tmid2.tv_sec + 1.0e-9*tmid2.tv_nsec) - ((double)tmid1.tv_sec+ 1.0e-9*tmid1.tv_nsec),
	    ((double)tmid1.tv_sec + 1.0e-9*tmid1.tv_nsec) - ((double)tstart.tv_sec+ 1.0e-9*tstart.tv_nsec),
	    ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) - ((double)tstart.tv_sec+ 1.0e-9*tstart.tv_nsec));
  }

  // Close our opened files.
  fclose(fin);
  fclose(fout);
  fclose(keyfile);

  // Free heap allocated memory
  free(data_in);
  free(dec_out);

  // Finished Rummimg Decryption
  return 1;
}
