#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/aes.h>

int main(int argc, char* argv[]){
// Seed Random with time
srand (time(NULL));

// Create Timing Variables
struct timespec tstart={0,0}, tend={0,0};
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
  else {
    // Using Default key and plaintext file names
    key_name = "key.txt";
    plaintext = "encryptedplaintext.txt";
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
  
  //unsigned char data_in[2048]; //536870911
  unsigned char *data_in; //536870911
  int f_size, pad;
  fscanf(data,"%i\n",&f_size);
  f_size = f_size/2;
  pad = 16-(f_size%16);
  data_in = malloc(f_size+pad+2);
  for(i=0;i<f_size;i++){
    fscanf(data,"%02x",&data_in[i]);
  }
  // Pad the data to make it an even 16 byte block size
  for(i=0;i<pad;i++){
    data_in[f_size+i] = data_in[i];
  }
  close(data);
  
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
  //unsigned char enc_out[2048];
  unsigned char *enc_out;
  enc_out = malloc(f_size+pad+2);
// Start timing here
clock_gettime(CLOCK_MONOTONIC, &tstart);
  AES_cbc_encrypt(data_in, enc_out, inputslength, &key, iv_enc, AES_ENCRYPT);
// Finish Timing Here
clock_gettime(CLOCK_MONOTONIC, &tend);
//   for(i=0;i<f_size;i++){
//     printf("%02x",enc_out[i]);
//   }
//   printf("\n");
//   printf("%i\n",sizeof(enc_out));
//   printf("%i\n",f_size;;

  
// Write the Encrypted data to the Encrypted data file
  for(i=0;i<f_size+pad;i++){
    fprintf(ct,"%02x",enc_out[i]);
    //printf("%02x",enc_out[i]);
  }
  close(ct);

  //Print out timing information
  if(timed){
    printf("some_long_computation took about %.10f seconds\n",((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) - ((double)tstart.tv_sec+ 1.0e-9*tstart.tv_nsec));
  }
  // Finished Rummimg Encryption
  return 1;
}
