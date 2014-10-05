////////////////////////////////////////////////////////////////////////////////
// AES-CBC-MAC Encryption Implementation - Meghan Caiazzo
// The purpose of this program is to take a key file containing an AES 
// key and encrypted a plaintext file using the AES encryption scheme 
// in Counter Block Chaining Mode (CBC) and provides calculation of a timestamp
// and MAC tag for message integrity. The MAC key is written out to an output file
// for decryption purposes. This program uses the OpenSSL api 
// function calls to perform this mode of encryption. The plaintext file to be 
// encrypted must contain only hexadecimal values (A-F, 0-9) and should not use
// 0x as a prefix for these values. The format of the ciphertext file produced 
// will contain the number of characters on the first line, the IV on the second line
// the encrypted plaintext starting on the third line followed by the timestamp
// and then the MAC tag. 
////////////////////////////////////////////////////////////////////////////////
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <openssl/aes.h>
#define MAX 4294967295 // Max file size that can be encrypted

int main(int argc, char* argv[]){
  // Seed Random with time
  srand (time(NULL));  
  
  //Variable declarations

  struct timespec tstart={0,0}, tend={0,0}, enc_time={0,0};

  unsigned char mac_key[AES_BLOCK_SIZE];
  unsigned char seed[64];
  unsigned char enc_key[18];
  unsigned char iv_enc[AES_BLOCK_SIZE];

  unsigned int tstamp;
  int i,j, pad, inputslength, inputByte, index1, check, num_bytes; 
  int timed = 0;  
  
  AES_KEY mac_encKey;
  AES_KEY encKey;  

  FILE *mac_key_file;
  FILE *keyfile;
  FILE *urand;
  FILE *ciphertext;
  FILE *plaintext;   
   
  unsigned char *clear_text;  
  unsigned char *output;
  unsigned char *mac;
  unsigned char* tstamp_buff[4];
  unsigned char *mac_out;
     

 //Usage and argument checking
//***********************************************************
  if(argc != 3 && argc != 4){
        printf("Usage: %s keyfile.txt plaintext.txt [-t]\n", argv[0]);
        exit(1);
    }
    else if(argc == 4 && !strncmp(argv[3],"-t",2)){
        timed = 1;
    }
//****************************************************
    //PLAINTEXT

 // Open the plaintext file specified by user for reading and check it exists
    plaintext = fopen(argv[2], "r");
    if(plaintext == NULL){
        fprintf(stderr, "Unable to open %s for reading!\n", argv[2]);
        exit(1);
    }
    
    // Read in the first value of the plaintext file to specify file length.
    check = fscanf(plaintext, "%i\n", &num_bytes);
    if(check != 1){
        fprintf(stderr, "Unable to read file size. Check file and try again\n");
        exit(1);
    }    
    
    //Calculate the number of bytes from the number of characters read in
    //set up padding in case of extra bytes at the end of file    
    num_bytes = num_bytes / 2;
    pad = 16-(num_bytes%16);
    inputslength = num_bytes + pad;

    //Allocate memory for the message input and output buffers

    clear_text = malloc(num_bytes+pad);
    memset(clear_text, 0x0, num_bytes+pad);
    output = malloc(num_bytes+pad);
    memset(output, 0x0, (num_bytes+pad));

      // Verify the plaintext file is less than 4294967295 bytes
    if(num_bytes > MAX){
        fprintf(stderr, "File is too large, Max file size is 4294967295 Bytes!\n");
        exit(1);
    }

    //Read the plaintext file into the clear_text buffer byte by byte
     for(i=0;i<num_bytes;i++){
     fscanf(plaintext,"%02hhx",&clear_text[i]);
   }

   //Pad the buffer to make sure AES blocks are lined up
    for(i=0;i<pad;i++){
    clear_text[num_bytes+i] = clear_text[i];
  }
  
  //We are done with the plaintext file, close it  
  fclose(plaintext);
//******************************************************************************
  //KEY

  // Load the Key from the key file
  keyfile = fopen("key.txt","r");
  if(keyfile == NULL){
    fprintf(stderr, "File 'key.txt' needed to preform encryption - run keygen first\n");
    exit(1);
  }
  
  //Read the key into an encryption key buffer
  for(i=0;i<16;i++){
    fscanf(keyfile,"%02hhx",&enc_key[i]);
  }  
  
  //Call to OpenSSL Api to set the encryption key
  AES_set_encrypt_key(enc_key, 128, &encKey);
//*************************************************************************
  //CIPHERTEXT

  // Open the file for the Ciphertext  
  ciphertext = fopen("ciphertext.txt","w+");

  // Print the size of the file to start of the cipher text file
  fprintf(ciphertext,"%i\n",(num_bytes*2));
  
 
  // Set Initialization Vector
  memset(iv_enc, 0x0, 16);
  for(i=0;i<16;i++){
    iv_enc[i]= (char)(rand()%255);
  }

  // Print initialization vector to the ciphertext file
  for(i=0;i<16;i++){
    fprintf(ciphertext,"%02hhx",iv_enc[i]);
  }
  fprintf(ciphertext,"\n");
//**********************************************************************************************************
  // Start total timing here
  if(timed)

    clock_gettime(CLOCK_MONOTONIC, &tstart);

  // Perform Encryption of the cleartext data
  AES_cbc_encrypt(clear_text, output, inputslength, &encKey, iv_enc, AES_ENCRYPT);

  // Get a stop time for how long the inital cleartext encryption took
  if(timed)
    clock_gettime(CLOCK_MONOTONIC, &enc_time);

//***************************************************************************************************************
  /* PART 2:    
    After finishing the encryption of the plaintext and setting up the ciphertext file, we calculate the timestamp
    and MAC tag to also append to the ciphertext file to provide message integrity.
*/
  //No longer need this buffer and memory, free it.
  free(clear_text);

  //realloc the output buffer now that we need more space
  unsigned char * plce_holder;
  plce_holder = realloc(output, (num_bytes+pad+AES_BLOCK_SIZE));
  output = plce_holder;
  

  //Zero out the realloc data 
  for(i = 0; i <16; i++)
    output[num_bytes+pad+i] = 0x0;

  // Allocate memory for the MAC
  mac = malloc(num_bytes+pad+AES_BLOCK_SIZE);
  memset(mac, 0x0, (num_bytes+pad+AES_BLOCK_SIZE));

  // Seed PRNG
  urand = fopen("/dev/urandom", "r");  
  fread(&seed, 8, 8, urand);
  
  
  // Perform the Actual PRNG seeding.
  RAND_seed(&seed, AES_BLOCK_SIZE);
  
  // Stage the MAC Key
  memset(mac_key, 0x0, AES_BLOCK_SIZE);
  
  // In our case for the MAC the IV is 0.
  memset(iv_enc, 0x0, AES_BLOCK_SIZE);
  
  //get timestamp
  tstamp = (unsigned)time(NULL);

  for(i = 0; i < 4; i++)
    output[num_bytes+pad+1+i] = (tstamp >> (32 - (i+1)*8)) & 0xFF;


  // Set up the mac key with random bytes.  
  RAND_bytes(mac_key,AES_BLOCK_SIZE);

  //set the encryption key
  AES_set_encrypt_key(mac_key, AES_BLOCK_SIZE*8, &mac_encKey);   
  
  //Allocate memory for a buffer to hold the last block of the AES encryption which is the MAC tag
  mac_out = malloc(AES_BLOCK_SIZE);
  memset(mac_out, 0x0, (AES_BLOCK_SIZE)); 
  
  //size and index variable declarations
  inputByte = inputslength+AES_BLOCK_SIZE;  
  index1 = inputByte -16;

  //Perform the encryption again with the ciphertext and timestamp as input 
  AES_cbc_encrypt(output, mac, inputByte, &mac_encKey, iv_enc, AES_ENCRYPT);  

  //Copy the last block of the AES encryption output to the buffer
  memcpy(mac_out, &mac[index1], 16);

  //Totally encryption is over, the rest is File I/O, stop the timing
  if(timed)
    clock_gettime(CLOCK_MONOTONIC, &tend);

  //Write the Ciphertext out to the ciphertext file
  for(i = 0; i < (num_bytes+pad); i++){
    fprintf(ciphertext,"%02hhx",output[i]);
  }
  fprintf(ciphertext,"\n");

  // Write the Time Stamp out to the ciphertext file
  for(i = 0; i < 4; i++){
    unsigned char t = output[num_bytes+pad+1+i] = (tstamp >> (32 - (i+1)*8)) & 0xFF;
    fprintf(ciphertext,"%02hhx", t);
  }
  fprintf(ciphertext,"\n");
  
  // Write the MAC out to the ciphertext file
  for(i = 0; i < AES_BLOCK_SIZE; i++){
    fprintf(ciphertext,"%02hhx",mac_out[i]);
  } 

  //Print out timing information if the -t tag was used to run encrypt
  if(timed)    
    printf("Encryption: %f\tTag: %f\tTotal: %f\n",
    ((double)enc_time.tv_sec + 1.0e-9*enc_time.tv_nsec) - ((double)tstart.tv_sec+ 1.0e-9*tstart.tv_nsec),
    ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) - ((double)enc_time.tv_sec+ 1.0e-9*enc_time.tv_nsec),    
    ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) - ((double)tstart.tv_sec+ 1.0e-9*tstart.tv_nsec));  
  
 
          
  // Write the key used for the MAC out to a file so we have it for decryption purposes
  mac_key_file = fopen("mac_key.txt","w");
  unsigned char * buff = (unsigned char*) &mac_encKey;
  for(i = 0; i < AES_BLOCK_SIZE; i++)
    fprintf(mac_key_file, "%02x", buff[i]);

  // Free Heap allocated memory
  fclose(mac_key_file);
  fclose(urand);
  fclose(ciphertext);  
  fclose(keyfile);
  free(mac);
  free(output);
  free(mac_out); 

  return 1;
}
//ENCRYPTION COMPLETE