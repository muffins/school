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
#include <time.h>
#include <openssl/aes.h>

#define AES_BLOCK_SIZE 32

int main(int argc, char* argv[]){
// Create Timing Variables
struct timespec tstart={0,0}, tend={0,0};

// Create Variables for holding the key_filename and ciphertext_filename
char *key_name, *ciphertext;
// Create a variable denoting if the process is to be timed
int timed = 0;
// Load the command line arguments
  if(argc != 1){
    if(argc != 3 && argc != 4){
      printf("Usage: %s keyfile.txt ciphertext.txt [-t]\n", argv[0]);
      exit(1);
    }
    else if(argc == 4 && !strncmp(argv[3],"-t",2)){
      timed = 1;
    }
    // Lets get our file names to some buffers
    key_name = argv[1];
    ciphertext = argv[2];
  }
// If no file names are specified then we load default file names
  else {
    // Using Default key and ciphertext file names
    key_name = "key.txt";
    ciphertext = "ciphertext.txt";
  }

  // Load the Key from the key file
  FILE *keyfile;
  keyfile = fopen(key_name,"r");
  if(keyfile == NULL){
    fprintf(stderr, "File '%s' needed to preform encryption - run keygen first\n",key_name);
    exit(1);
  }
  unsigned char key_in[34];
  int i,j;
  for(i=0;i<32;i++){
    fscanf(keyfile,"%02hhx",&key_in[i]);
  }
  fclose(keyfile);
  // Create an AES Key
  // typedef struct aes_key_st AES_KEY;
  AES_KEY key;
  
  // Set the AES Decryption Key to the Key that was imported from key.txt
  //int AES_set_decrypt_key(const unsigned char *userKey,
  //                        const int bits,
  //	                  AES_KEY *key);
  AES_set_decrypt_key(key_in, 256, &key);

  
  // Open the Ciphertext file
  FILE *data;
  data = fopen(ciphertext,"r");
  if(data == NULL){
    fprintf(stderr, "File '%s' not found... Please provide data to encrypt.\n",ciphertext);
    exit(1);
  }

  // Load FileSize
  unsigned char *data_in;
  int f_size, pad;
  fscanf(data,"%i\n",&f_size);
  
  // Load Initialization Vector
  unsigned char iv_dec[34]="";
  int new_line_val;
  unsigned char new_line_char;
  for(i=0;i<32;i++){
    fscanf(data,"%02hhx",&iv_dec[i]);
  }
  fscanf(data,"%c",&new_line_char); // Here we grab the line between the IV and the encrypted data

  // Calculate the PAD used on the data and load the data.
  f_size = f_size/2;
  pad = 32 - (f_size%32);
  
  // Allocate memory to store the cipher text
  //data_in = malloc(f_size+pad+2);
  data_in = malloc(f_size+pad);
  if(data_in == NULL){
    fprintf(stderr, "Unable to allocate memory for writing!\n");
    exit(1);
  }

  for(i=0;i<=f_size+pad;i++){
    fscanf(data,"%02hhx",&data_in[i]);
  }
  fclose(data);

  // Decrypt the Data
  //void AES_cbc_encrypt(const unsigned char *in,
  //                     unsigned char *out,
  //	               size_t length,
  //                     const AES_KEY *key,
  //	               unsigned char *ivec,
  //                     const int enc);
  size_t inputslength = f_size+pad;
  unsigned char *dec_out;

  // Allocate memory to store the clear text
  //dec_out = malloc(f_size+pad+2);
  dec_out = malloc(f_size+pad);
  if(dec_out == NULL){
    fprintf(stderr, "Unable to allocate memory for writing!\n");
    exit(1);
  }

  // Start timing here
  if(timed)
    clock_gettime(CLOCK_MONOTONIC, &tstart);

  // Perform Decryption
  AES_cbc_encrypt(data_in, dec_out, inputslength, &key, iv_dec, AES_DECRYPT);

  // Finish Timing Here
  if(timed)
    clock_gettime(CLOCK_MONOTONIC, &tend);  

  // Write the Decrypted data to the Decrypted data file
  FILE *pt;
  pt = fopen("decryptedplaintext.txt","w+");
  if(pt == NULL){
    fprintf(stderr, "File 'decryptedplaintext.txt' couldn't be opened or created... its your problem now\n");
    exit(1);
  }
  // Print the size of the file to start of the decoded plaintext file
  fprintf(pt,"%i\n",(f_size*2));
  for(i=0;i<f_size;i++){
    fprintf(pt,"%02x",dec_out[i]);
  }
  fclose(pt);
  //Print out timing information
  if(timed){
    printf("some_long_computation took about %.10f seconds\n",((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) - ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec));
  }

  // Free heap allocated memory
  free(data_in);
  free(dec_out);

  // Finished Rummimg Decryption
  return 1;
}
