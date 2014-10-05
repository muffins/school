#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/aes.h>

int main(int argc, char* argv[]){
// Create Timing Variables
struct timespec tstart={0,0}, tend={0,0};
char *key_name, *ciphertext;
int timed = 0;
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
    fscanf(keyfile,"%02x",&key_in[i]);
  }
  close(keyfile);

// Create an AES Key
// typedef struct aes_key_st AES_KEY;
  AES_KEY key;
  
// Set the AES Decryption Key to the Key that was imported from key.txt
//int AES_set_decrypt_key(const unsigned char *userKey,
//                        const int bits,
//	                  AES_KEY *key);
  AES_set_decrypt_key(key_in, 128, &key);

  
// Load the Data for Decryption
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
  int new_line_val;
  for(i=0;i<AES_BLOCK_SIZE;i++){
    fscanf(data,"%02x",&new_line_val);
    iv_dec[i]=(unsigned char) new_line_val;
  }
  fscanf(data,"%c",&new_line_val);

  f_size = f_size/2;
  pad = 16-(f_size%16);
  data_in = malloc(f_size+pad+2);
  for(i=0;i<=f_size+pad;i++){
    fscanf(data,"%02x",&data_in[i]);
  }
  close(data);

  
// Uncomment Below to check ciphertext
//    for(i=0;i<(j/2);i++){
//      printf("%02x",data_in[i]);
//    }

// Decrypt the Data
//void AES_cbc_encrypt(const unsigned char *in,
//                     unsigned char *out,
//	               size_t length,
//                     const AES_KEY *key,
//	               unsigned char *ivec,
//                     const int enc);
  size_t inputslength = f_size+pad;
  unsigned char *dec_out;
  dec_out = malloc(f_size+pad+2);
// Start timing here
clock_gettime(CLOCK_MONOTONIC, &tstart);
  AES_cbc_encrypt(data_in, dec_out, inputslength, &key, iv_dec, AES_DECRYPT);
// Finish Timing Here
clock_gettime(CLOCK_MONOTONIC, &tend);  

// Write the Decrypted data to the Decrypted data file
  FILE *pt;
  pt = fopen("decryptedplaintext.txt","w+");
  if(pt == NULL){
    fprintf(stderr, "File 'decryptedplaintext.txt' couldn't be opened or created... its your problem now\n");
    exit(1);
  }
  // Print the size of the file to start of the cipher text file
  fprintf(pt,"%i\n",(f_size*2));
  for(i=0;i<f_size;i++){
    fprintf(pt,"%02x",dec_out[i]);
  }
  close(pt);
  
  //Print out timing information
  if(timed){
    printf("some_long_computation took about %.10f seconds\n",((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) - ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec));
  }
  // Finished Rummimg Decryption
  return 1;
}
