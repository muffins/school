////////////////////////////////////////////////////////////////////////////////
// AES-CBC-MAC Decryption Implementation - Meghan Caiazzo
// Modern Cryptography part 2
//
// The purpose of this program is to take a key file containing an AES 
// key, a ciphertext file that has been encrypted with an AES-CBC encryption
// scheme, a mac key file and decrypt the ciphertext to produce and very the
// original plaintext message. This file will read in the specifically formatted
// ciphertext file and pull out the file size, IV, Ciphertext, timestamp and 
// MAC tag for verification. Once MAC tag is recomputed and then verified from
// by the MAC tag in the ciphertext file, AES-CBC decryption will be performed.
// This program uses the OpenSSL api function calls to perform this mode of decryption.
// The ciphertext file to be decrypted must contain only hexadecimal values (A-F, 0-9)
// and should not use 0x as a prefix for these values. The format of the ciphertext file 
// provided will contain the number of characters on the first line, the IV on the second line
// the encrypted plaintext starting on the third line followed by the timestamp
// and then the MAC tag. 
////////////////////////////////////////////////////////////////////////////////
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/aes.h>

#define REPLAY_THRESH 120

int main(int argc, char* argv[]){  
  
  //Variable declaration

  struct timespec tstart={0,0}, tend={0,0}, tag_time={0,0}, tag_verify={0,0};  
  int num_bytes, pad;  
  int i, j, new_line_val, timed = 0;
  long filestream_start=0;   
  size_t inputslength;    

  
  unsigned char key_in[18];
  unsigned char mac_key[AES_BLOCK_SIZE];
  unsigned char timestamp_buff[4]; 
  unsigned char mac_iv[AES_BLOCK_SIZE]; 
  unsigned char seed[64];  
  
  unsigned char *decrypted_plaintext_buff; 
  unsigned char *plc_holder; 
  unsigned char *ciphertext_buff; 
  unsigned char *plaintext_buff; 
  unsigned char *mac_buff;  
 
  unsigned char tmp=0x0; 
  unsigned int tstamp_o=0, tstamp_n=0, ret=0;   
  
  AES_KEY key;
  AES_KEY mac_enc_key;  

  FILE *mac_key_file;
  FILE *keyfile;
  FILE *input;
  FILE *pt;  
  

   //Usage and argument checking
//****************************************************************************
  if(argc != 3 && argc != 4){
        printf("Usage: %s keyfile.txt plaintext.txt [-t]\n", argv[0]);
        exit(1);
    }
    else if(argc == 4 && !strncmp(argv[3],"-t",2)){
        timed = 1;
    }
//****************************************************************************
  // Open Key file
  keyfile = fopen("key.txt","r");
  if(keyfile == NULL){
    fprintf(stderr, "File 'key.txt' needed to perform decryption - run keygen first\n");
    exit(1);
  }
  
  //Load the key
  for(i=0;i<16;i++){
    fscanf(keyfile,"%02hhx",&key_in[i]);
  }
  
  // Set the AES Decryption Key using the OpenSSL api 
  AES_set_decrypt_key(key_in, 128, &key);

//****************************************************************************
  //Ciphertext file
  
  // Open the Ciphertext file
  input = fopen("ciphertext.txt","r");  
  fscanf(input,"%i\n",&num_bytes);  

  //**************************************************************************
  // IV Vector

  //Allocate memory 
  unsigned char iv_dec[AES_BLOCK_SIZE];
  memset(iv_dec, 0x0, AES_BLOCK_SIZE);
  
  // Load Initialization Vector
  for(i=0;i<AES_BLOCK_SIZE;i++){
    fscanf(input,"%02hhx",&tmp);
    iv_dec[i] = tmp;
  }
  fscanf(input,"%c",&tmp); 

  //**************************************************************************
  //Scanning the file 
  //**************************************************************************
    //Timestamp

  //Record the current filestream location 
  filestream_start = ftell(input);

  // compute the pad
  pad = 32-(num_bytes%32);

  // clear the timestamp buffer
  memset(timestamp_buff, 0x0, 4);

  //Retrieve the timestamp
  fseek(input, (num_bytes+pad), SEEK_CUR);  
  for(i = 0; i < 4; i++){
    fscanf(input, "%02hhx", &tmp);  
    timestamp_buff[i] = tmp; 
    tstamp_o += ((unsigned int)tmp << (32-(i+1)*8));
  }
  
  tstamp_n = (unsigned)time(NULL);
  if((tstamp_n - tstamp_o) > REPLAY_THRESH){
    fprintf(stderr, "Replay Attack Detected.  Exiting.\n");
    exit(1);
  }
//*****************************************************************************
  //Ciphertext

  //Go to the beginning of the ciphertext
  fseek(input, filestream_start, SEEK_SET); 

  //Calculate pad
  num_bytes = num_bytes/2;
  pad = 16-(num_bytes%16);
  inputslength = num_bytes+pad;

  // Allocate memory to store the cipher text
  ciphertext_buff = malloc(num_bytes+pad+AES_BLOCK_SIZE);
  memset(ciphertext_buff, 0x0, (num_bytes+pad+AES_BLOCK_SIZE));

  // Allocate memory for the output buffer.
  mac_buff = malloc(num_bytes+pad+AES_BLOCK_SIZE);
  memset(mac_buff, 0x0, (num_bytes+pad+AES_BLOCK_SIZE));
  
  // Get Ciphertext
  for(i = 0; i < (num_bytes+pad); i++)
    fscanf(input,"%02hhx",&ciphertext_buff[i]);

  //Add timestamp to the ciphertext
  for(i = 0; i < 4; i++)
    ciphertext_buff[num_bytes+pad+1+i] = timestamp_buff[i];
//**********************************************************************************
  //MAC Key
  
  memset(mac_key, 0x0, AES_BLOCK_SIZE);

  // Get the MAC key from the mac_key file
  mac_key_file = fopen("mac_key.txt", "r");

  //Store the key
  for(i = 0; i < 16; i++)
    fscanf(mac_key_file, "%02hhx", &mac_key[i]);

  //Set the MAC key
  AES_set_encrypt_key(mac_key, AES_BLOCK_SIZE*8, &mac_enc_key);

  // MAC IV is 0 
  memset(mac_iv, 0x0, AES_BLOCK_SIZE);

  // Start the time for total decryption
  if(timed)    
    clock_gettime(CLOCK_MONOTONIC, &tstart);

  //Compute the encryption again to verify against
  AES_cbc_encrypt(ciphertext_buff, mac_buff, (inputslength + AES_BLOCK_SIZE), &mac_enc_key, mac_iv, AES_ENCRYPT);

  // Get the time it took to compute the MAC tag
  if(timed)    
    clock_gettime(CLOCK_MONOTONIC, &tag_time);
//***************************************************************************************************
  //Message Verification
  
  //Find the MAC tag in Ciphertext file and read it into buffer
  fseek(input, ( sizeof(int)*2+1 ), SEEK_CUR);
  
  //Check byte by byte if the MAC tag we just computed matches the MAC tag from the ciphertext file
  for(i = inputslength; i < (inputslength+AES_BLOCK_SIZE); i++){
    fscanf(input,"%02hhx",&tmp); 
    if(tmp != mac_buff[i]){
      fprintf(stderr, "Data Corruption.. Exiting!\n");
      exit(1);
    }
  }

  // Store the time it took to verify the message
  if(timed)    
    clock_gettime(CLOCK_MONOTONIC, &tag_verify);

  //We are done with this buffer, free it
  free(mac_buff);

//************************************************************************************************
  //Decryption

  //Realloc the buffer for further use
  plc_holder = realloc(ciphertext_buff, num_bytes+pad);
  ciphertext_buff = plc_holder;
  inputslength = num_bytes+pad;

  // Allocate memory to store the clear text
  decrypted_plaintext_buff = malloc(num_bytes+pad);
  memset(decrypted_plaintext_buff, 0x0, num_bytes+pad); 

  // Perform Decryption using OpenSSL api call
  AES_cbc_encrypt(ciphertext_buff, decrypted_plaintext_buff, inputslength, &key, iv_dec, AES_DECRYPT);

  //Get the stop time for total decryption
  if(timed)    
    clock_gettime(CLOCK_MONOTONIC, &tend);


  // Write the decrypted message to the decryptedplaintext file
  pt = fopen("decryptedplaintext.txt","w+");
  
  // Print the size of the file to start of the decoded plaintext file
  fprintf(pt,"%i\n",(num_bytes*2));
  for(i=0;i<num_bytes;i++){
    fprintf(pt,"%02x",decrypted_plaintext_buff[i]);
  }
  
  //Print out timing information if decryption is ran with the -t 
  if(timed)
    printf("Decryption: %f\tTag Verify: %f\tTag: %f\tTotal: %f\n", 
      ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) - ((double)tag_verify.tv_sec+ 1.0e-9*tag_verify.tv_nsec),
      ((double)tag_verify.tv_sec + 1.0e-9*tag_verify.tv_nsec) - ((double)tag_time.tv_sec+ 1.0e-9*tag_time.tv_nsec),
      ((double)tag_time.tv_sec + 1.0e-9*tag_time.tv_nsec) - ((double)tstart.tv_sec+ 1.0e-9*tstart.tv_nsec),
      ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) - ((double)tstart.tv_sec+ 1.0e-9*tstart.tv_nsec));      

  // Free heap allocated memory
  fclose(input);
  fclose(keyfile);
  fclose(pt);
  fclose(mac_key_file);
  free(ciphertext_buff);
  free(decrypted_plaintext_buff);

  return 1;
}
