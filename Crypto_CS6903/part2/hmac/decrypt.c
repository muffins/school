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

int main(int argc, char* argv[]){
// Create Timing Variables
struct timespec tstart={0,0}, tmid1={0,0}, tmid2={0,0}, tend={0,0};

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
  unsigned char key_in[18];
  int i,j;
  for(i=0;i<16;i++){
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
  AES_set_decrypt_key(key_in, 128, &key);

  
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
  unsigned char iv_dec[AES_BLOCK_SIZE]="";
  int new_line_val = 0;
  char new_line_char;
  for(i=0;i<AES_BLOCK_SIZE;i++){
    fscanf(data,"%02hhx",&iv_dec[i]);
  }
  fscanf(data,"%c",&new_line_char); // Here we grab the line between the IV and the sha_key
  
  // Load the SHA256 Key
  unsigned char sha_key[32]="";
  for(i=0;i<32;i++){
    fscanf(data,"%02hhx",&sha_key[i]);
  }
  
  fscanf(data,"%c",&new_line_char); // Here we grab the line between the SHA_Key and the timestamp
  
  // Load the Timestamp
  unsigned char ts[11]="";
  memset(ts,0,11);
  for(i=0;i<10;i++){
    fscanf(data,"%02hhx",&ts[i]);
  }
  int encrypt_time;
  sscanf(ts, "%d", &encrypt_time);
  time_t epoch_time = time(NULL);
//  printf("%i %i %i\n",encrypt_time, (int)epoch_time, ((int)epoch_time - encrypt_time));
//   if(abs((int)epoch_time - encrypt_time) > 90){
//     printf("Unless it is suspected that the sender traveled back in time you shouldn't decode this!\n");
//     exit(1);
//   }

  
  // Calculate the PAD used on the data and load the data.
  f_size = f_size/2;
  pad = 16-(f_size%16);
  int padding;
  padding = 32-((f_size+pad)%32);
  
  // Allocate memory to store the cipher text
  data_in = malloc(f_size+pad+padding);
  memset(data_in,0,(f_size+pad+padding));
  if(data_in == NULL){
    fprintf(stderr, "Unable to allocate memory for writing!\n");
    exit(1);
  }

  // Load the ciphertext data
  for(i=0;i<f_size+pad;i++){
    fscanf(data,"%02hhx",&data_in[i]);
  }

  fscanf(data,"%c",&new_line_char); // Here we grab the line between the SHA_Key and the timestamp

  // Load the MAC from the file
  unsigned char sha_data[32]="";
  unsigned char sha_keep[32]=""; // Some shit is going down here and I don't know why the first byte gets
                                 // Overwritten but it does.
  for(i=0;i<32;i++){
    fscanf(data,"%02hhx",&sha_data[i]);
    sha_keep[i] = sha_data[i];
  }
  
  fclose(data);

  // Calculate the HMAC values
  // Append Time to Encrcrypted data
  for(i=0;i<11;i++){
   data_in[f_size+pad+i]=ts[i];
  }
  //Start Timing
  if(timed)
    clock_gettime(CLOCK_MONOTONIC, &tstart);
  unsigned char* digest;
  digest = HMAC(EVP_sha256(), sha_key, 32, data_in, (f_size+pad+padding), NULL, NULL);
  
  // Get Mid 1 time
  if(timed)
    clock_gettime(CLOCK_MONOTONIC, &tmid1);

  /*
  unsigned char shaString[64];
  for(i = 0; i < 32; i++)
       sprintf(&shaString[i*2], "%02x", (unsigned int)digest[i]);
  */

  // Print an error if the data in the MACs doesn't match
  for(i=0;i<32;i++){
//     printf("%02x %02x\n", shaString[i], sha_data[i]);
    //if(shaString[i] != sha_data[i]){
    if(digest[i] != sha_data[i]){
      printf("Error - The MAC doesn't match, maybe for Karate Lessons\n");
      exit(1);
    }
  }

  // Get Mid 2 time
  if(timed)
    clock_gettime(CLOCK_MONOTONIC, &tmid2);

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
  dec_out = malloc(f_size+pad);
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
    printf("Decryption: %.10f s Tag Verify: %.10f s Tag: %.10f s Total: %.10f s\n",((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) - ((double)tmid2.tv_sec+ 1.0e-9*tmid2.tv_nsec),
	                                                                           ((double)tmid2.tv_sec + 1.0e-9*tmid2.tv_nsec) - ((double)tmid1.tv_sec+ 1.0e-9*tmid1.tv_nsec),
	                                                                           ((double)tmid1.tv_sec + 1.0e-9*tmid1.tv_nsec) - ((double)tstart.tv_sec+ 1.0e-9*tstart.tv_nsec),
	                                                                           ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) - ((double)tstart.tv_sec+ 1.0e-9*tstart.tv_nsec));
  }

  // Free heap allocated memory
  free(data_in);
  free(dec_out);

  // Finished Rummimg Decryption
  return 1;
}
