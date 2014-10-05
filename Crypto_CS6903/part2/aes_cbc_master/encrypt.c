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
////////////////////////////////////////////////////////////////////////////////
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/aes.h>

int main(int argc, char* argv[]){
// Seed Random with time
srand (time(NULL));

// Create Timing Variables
struct timespec tstart={0,0}, tend={0,0};

// Create Variables to hole the key_filename and plaintext.hex_filename
char *key_name, *plaintext;
int timed = 0;
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
    fscanf(keyfile,"%02x",&key_in[i]);
  }
  fclose(keyfile);

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
  unsigned char iv_enc[AES_BLOCK_SIZE]="";
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
  //data_in = malloc(f_size+pad+2);
  data_in = malloc(f_size+pad);
  memset(data_in, 0x0, f_size+pad);
  if(data_in == NULL){
    fprintf(stderr, "Unable to allocate memory for reading!\n");
    exit(1);
  }

  for(i=0;i<f_size;i++){
    fscanf(data,"%02x",&data_in[i]);
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

  // Encrypt the Data
  //void AES_cbc_encrypt(const unsigned char *in,
  //                     unsigned char *out,
  //	               size_t length,
  //                     const AES_KEY *key,
  //	               unsigned char *ivec,
  //                     const int enc);

  size_t inputslength = f_size + pad;
  unsigned char *enc_out;

  // Allocate memory to store the encrypted text
  //enc_out = malloc(f_size+pad+2);
  enc_out = malloc(f_size+pad);
  memset(enc_out, 0x0, f_size+pad);
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
    clock_gettime(CLOCK_MONOTONIC, &tend);

  
  // Write the Encrypted data to the Encrypted data file
  for(i=0;i<f_size+pad;i++){
    fprintf(ct,"%02x",enc_out[i]);
    //printf("%02x",enc_out[i]);
  }
  fclose(ct);

  //Print out timing information
  if(timed){
    printf("some_long_computation took about %.10f seconds\n",((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) - ((double)tstart.tv_sec+ 1.0e-9*tstart.tv_nsec));
  }

  // Free Heap allocated memory
  free(enc_out);
  free(data_in);

  // Finished Rummimg Encryption
  return 1;
}
