////////////////////////////////////////////////////////////////////////////////
// AES CBC Encryption
// Modern Cryptography Project Part 2
// Description: This code preforms encryption using the AES CBC.
// scheme. The data to be encrypted is input in a file of the following form:
//         -Line 1: Number of characters of data in the file
//         -Line 2: Data in hex representation (A is 41, B is 42, etc.)
// The output from running encryption is of the following form:
//         -Line 1: Number of characters of data in the file
//         -Line 2: Initialization Vector in hex representation (A is 41, B is 42, etc.)
//         -Line 3: Encrypted Data in hex representation(A is 41, B is 42, etc.)
// During encryption the inccoming data is padded so that it alines with a 
// block boundary, the data padding is not added to the number of characters
// shown on line 1 of the ciphertext file.
// Usage:
//       ./encrypt <key_filename> <plaintext.hex_filename> [-t]
// The use of -t will time the operation of the encryption, which does not
// include the associated file IO for loading the key or the data. Note that
// the time is always calculated the flag determines if the time is printed.
// Key_filename and plaintext.hex_filename must be supplied to print the timeing
// however if timing isn't desired then the default names for the key_filename
// and plaintext.hex_filename are key.txt and plaintext.txt repectively
//
//
// Enc’(k,m): compute a time-stamp ts,
//            c1=Enc(k1,m),
//            t=Tag(k2, c1|ts);
//   finally, send (ts, c1, t)
//
// SHA2 - 256 bit KEY
////////////////////////////////////////////////////////////////////////////////
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>

int main(int argc, char* argv[]){
// Seed Random with time
srand (time(NULL));

// Create Timing Variables
struct timespec tstart={0,0}, tmid1={0,0}, tmid2={0,0}, tend={0,0};

// Create Variables to hole the key_filename and plaintext.hex_filename
char *key_name, *plaintext;
int timed = 0;

// Get the filenames from commandline
  if(argc != 1){
    if(argc != 3 && argc != 4){
      printf("Usage: %s keyfile.txt plaintext.txt [-t]\n", argv[0]);
      exit(1);
    }
    else if(argc == 4 && !strncmp(argv[3],"-t",2)){
      timed = 1;
    }
    // Lets get our file names to some buffers
    key_name = argv[1];
    plaintext = argv[2];
  }
// If no filenames are given then use default names for the input files
  else {
    // Using Default key and plaintext file names
    key_name = "key.txt";
    plaintext = "plaintext.txt";
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

// Create the key for SHA256
  unsigned char sha_key[32];
  memset(sha_key,0x0, 32);
  for(i=0;i<32;i++){
    sha_key[i]= (unsigned char)(rand()%255);
  }
  
// Create an AES Key
// typedef struct aes_key_st AES_KEY;
  AES_KEY key;
  
// Set the AES Encryption Key to the Key that was imported from key.txt
//int AES_set_encrypt_key(const unsigned char *userKey,
//                        const int bits,
//	                  AES_KEY *key);
  AES_set_encrypt_key(key_in, 128, &key);
  
// Open the file for the Ciphertext
  FILE *ct;
  ct = fopen("ciphertext.txt","w+");
  if(ct == NULL){
    fprintf(stderr, "File 'ciphertext.txt' couldn't be opened or created... its your problem now\n");
    exit(1);
  }  
// Set Initialization Vector
  unsigned char iv_enc[AES_BLOCK_SIZE];
  memset(iv_enc,0x0,AES_BLOCK_SIZE);
  for(i=0;i<16;i++){
    iv_enc[i]= (char)(rand()%255);
  }
  
// Load the Data for Encryption
  FILE *data;
  data = fopen(plaintext,"r");
  if(data == NULL){
    fprintf(stderr, "File '%s' not found... Please provide data to encrypt.\n",plaintext);
    exit(1);
  }
  
  unsigned char *data_in;
  int f_size, pad;

  // Read in the filesize and Calulate the padding for the data.
  fscanf(data,"%i\n",&f_size);
  f_size = f_size/2;
  pad = 16-(f_size%16);
  
  // Allocate memory to store the clear text
  data_in = malloc(f_size+pad+32);
  memset(data_in,0,(f_size+pad+32));
  if(data_in == NULL){
    fprintf(stderr, "Unable to allocate memory for reading!\n");
    exit(1);
  }

  for(i=0;i<f_size;i++){
    fscanf(data,"%02hhx",&data_in[i]);
  }
  // Pad the data to make it an even 16 byte block size
  // Here the data from the beginning of the encryption is repeated to add some
  // abiguity to the data pad.
  for(i=0;i<pad;i++){
    data_in[f_size+i] = data_in[i];
  }
  fclose(data);
  
  // Print the size of the file to start of the cipher text file
  fprintf(ct,"%i\n",(f_size*2));

  // Print initial value to file
  for(i=0;i<AES_BLOCK_SIZE;i++){
    fprintf(ct,"%02X",iv_enc[i]);
  }
  fprintf(ct,"\n");
  
  // Print the SHA256 Key to the ciphertext file
  for(i=0;i<32;i++){
    fprintf(ct,"%02X",sha_key[i]);
  }
  fprintf(ct,"\n");

  // Get Timestamp aka Epoch time
  time_t epoch_time = time(NULL);
  unsigned char ts[11] = "";
  memset(ts,0x0,11);
  sprintf(ts,"%d", (int)epoch_time);
  
//Print timestamp to filenames
  i = 0;
  while(ts[i] != '\0'){
    fprintf(ct,"%02X",ts[i]);
    i++;
  }
  fprintf(ct,"\n");

  // Encrypt the Data
  //void AES_cbc_encrypt(const unsigned char *in,
  //                     unsigned char *out,
  //	               size_t length,
  //                     const AES_KEY *key,
  //	               unsigned char *ivec,
  //                     const int enc);

  size_t inputslength = f_size + pad;
  unsigned char *enc_out;
  int padding;
  padding = 32-((f_size+pad)%32);

  // Allocate memory to store the encrypted text
  enc_out = malloc(f_size+pad+padding+2);
  memset(enc_out,0,(f_size+pad+padding+2));
  if(enc_out == NULL){
    fprintf(stderr, "Unable to allocate memory for writing!\n");
    exit(1);
  }

  // Start timing here
  if(timed)
    clock_gettime(CLOCK_MONOTONIC, &tstart);

  // Perform Encryption
  AES_cbc_encrypt(data_in, enc_out, inputslength, &key, iv_enc, AES_ENCRYPT);

  // Finish Timing Here
  if(timed)
    clock_gettime(CLOCK_MONOTONIC, &tmid1);

  // Write the Encrypted data to the Encrypted data file
  for(i=0;i<f_size+pad;i++){
    fprintf(ct,"%02x",enc_out[i]);
  }
  
  // Finish Timing Here
  if(timed)
    clock_gettime(CLOCK_MONOTONIC, &tmid2);
  
  // Calcuate the HMAC with the data being the CT appended with the ts
  // Append Operation
  for(i=0;i<11;i++){
   enc_out[f_size+pad+i]=ts[i];
  }
  unsigned char* digest;

  digest = HMAC(EVP_sha256(), sha_key, 32, enc_out, (f_size+pad+padding), NULL, NULL);

/*
  printf("digest - ");
  for(i = 0; i < 32; i++)
    printf("%02x", digest[i]);
  printf("\n");
*/

  fprintf(ct,"\n");
  if(timed)
    clock_gettime(CLOCK_MONOTONIC, &tend);
  
  /*
  unsigned char shaString[32];
  for(i = 0; i < 32; i++)
       sprintf(&shaString[i*2], "%02x", (unsigned int)digest[i]);
      */

  for(i = 0; i < 32; i++){
	  //fprintf(ct,"%02x", shaString[i]);
    fprintf(ct, "%02x", digest[i]);
  }
  
  fclose(ct);

  //Print out timing information
  if(timed){
    printf("Encryption: %.10f s Tag: %.10f s Total: %.10f s\n",((double)tmid1.tv_sec + 1.0e-9*tmid1.tv_nsec) - ((double)tstart.tv_sec+ 1.0e-9*tstart.tv_nsec),
	                                                       ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) - ((double)tmid2.tv_sec+ 1.0e-9*tmid2.tv_nsec),
	                                                       (((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) - ((double)tmid2.tv_sec+ 1.0e-9*tmid2.tv_nsec))+(((double)tmid1.tv_sec + 1.0e-9*tmid1.tv_nsec) - ((double)tstart.tv_sec+ 1.0e-9*tstart.tv_nsec)));
  }

  // Free Heap allocated memory
  free(enc_out);
  free(data_in);

  // Finished Rummimg Encryption
  return 1;
}
