/*
 * Nick Anderson, 04/29/2014
 *
 * hybridencrypt.c
 *
 * An implementation of RSA-OAEP Public Key encryption.  This program
 * expects as input a publickey.txt file, followed by a cleartext file
 * in the following format:
 * Line 1: A single unsigned integer containing the 'length' of the
 *         cleartext data.  This length is the number of ASCII characters
 *         contained in the file.
 * Line 2: Hexadecimal values representing the ASCII cleartext.  Every
 *         character encountered from line 2 forward should be A-F or 0-9
 *         
 * 
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/hmac.h>

// Globally defined sizes, all in bits
#define REPLAY_THRESH 300
#define RSA_KEY_BITS 2048
#define SYM_KEY_BITS 128 // AES Symmetric Key
#define SHA_KEY_BITS 256

int main(int argc, char* argv[]){

  // Counter and placeholder variables
  int i, j, sha_padding, pad, ret, timed=0;
  unsigned char tmp=0x0;


  // Variable for how many characters are in the file.
  unsigned int f_size = 0;
  unsigned int tstamp_o=0, tstamp_n=0;
  unsigned char tstamp_buff[4];

  size_t rsa_key_bytes = RSA_KEY_BITS/8;
  size_t sym_key_bytes = SYM_KEY_BITS/8;
  size_t sha_key_bytes = SHA_KEY_BITS/8;

  // Timing Variables
  clock_t start, stop, asym, sym, hmac;

  // Pointers to filenames
  unsigned char *ciphertext_fname = NULL;
  unsigned char *privatekey_fname = NULL;
  unsigned char *publickey_fname = NULL;

  // RSA Clear and Cipher text buffers
  // We use RSA Pub Key to encrypt the sym key and the HMAC key
  // Plus 1 for a nulbyte from snprintf
  unsigned char rsa_cleartext_buff[rsa_key_bytes];
  // See OpenSSL RSA_Public_Encrypt for specification on ciphertext size
  unsigned char rsa_ciphertext_buff[rsa_key_bytes]; 

  // Symmetric Encryption Clear, Cipher, and Key Buffs
  unsigned char *sym_cleartext_buff = NULL;  
  unsigned char *sym_ciphertext_buff = NULL;
  unsigned char symmetric_key[sym_key_bytes];
  unsigned char symmetric_iv[sym_key_bytes];

  // Allocate buffers for SHA MAC
  unsigned char sha_key[sha_key_bytes];
  unsigned char sha_buff_o[sha_key_bytes];
  unsigned char *sha_buff_n = NULL;

  // PRNG Seed buffer
  unsigned char seed[rsa_key_bytes];
  
  // File pointers
  FILE *publickey_file;
  FILE *privatekey_file;
  FILE *urand;
  FILE *fout;
  FILE *fin;

  // OpenSSL Structs
  RSA *privkey = NULL;
  AES_KEY aes_key;

  // Load the command line arguments
  // ./hybriddecrypt publickey.txt secretkey.txt ciphertext.txt > decryptedplaintext.txt
  if(argc != 1){
    if(argc != 4 && argc != 5){
      printf("Usage: %s publickey.txt secretkey.txt ciphertext.txt [-t]\n", argv[0]);
      exit(1);
    } else if(argc == 5 && !strncmp(argv[4],"-t",2)) {
      timed = 1;
    }
    // Lets get our file names to some buffers
    publickey_fname = argv[1];
    privatekey_fname = argv[2];
    ciphertext_fname = argv[3];
  } else {
    // Using Default key and ciphertext file names
    privatekey_fname = "secretkey.txt";
    publickey_fname = "publickey.txt";
    ciphertext_fname = "ciphertext.txt";
  }

  // Open the file for the Ciphertext
  fout = fopen("decryptedplaintext.txt","w+");
  if(fout == NULL){
    fprintf(stderr, "ERROR: Unable to open 'decryptedplaintext.txt' for writing!\n");
    exit(-1);
  }

  // Load the Data for Encryption  
  fin = fopen(ciphertext_fname,"r");
  if(fin == NULL){
    fprintf(stderr, "ERROR: Unable to open '%s' for reading!\n",ciphertext_fname);
    exit(-1);
  }

  // Load the public key file
  publickey_file = fopen(publickey_fname,"r");
  if(publickey_file == NULL){
    fprintf(stderr, "ERROR: File '%s' needed to preform encryption - run hybridkeygen first\n", publickey_fname);
    exit(-1);
  }

  // Load the public key file
  privatekey_file = fopen(privatekey_fname,"r");
  if(privatekey_file == NULL){
    fprintf(stderr, "ERROR: File '%s' needed to preform encryption - run hybridkeygen first\n", privatekey_fname);
    exit(-1);
  }

  // Open dev rand to seed our random data.
  urand = fopen("/dev/urandom","r");
  if(urand == NULL){
      fprintf(stderr, "ERROR: Unable to open /dev/urandom for reading!\n");
      exit(-1);
  }

  // Read the rand data from /dev/urandom
  ret = fread(&seed, sizeof(char), rsa_key_bytes, urand);
  if(ret < rsa_key_bytes){
      fprintf(stderr, "ERROR: Unable to obtain random seed from /dev/urandom!\n");
      exit(-1);
  }
  
  // Seed the PRNG
  RAND_seed(&seed, rsa_key_bytes);

  // Load FileSize
  fscanf(fin,"%u\n",&f_size);
  
  f_size = f_size/2;
  pad = sym_key_bytes - (f_size % sym_key_bytes);

  /* Grab the timestamp from the cipher text file.  This should exist on Line 4 */
  for(i = 0; i < 4; i++){
    fscanf(fin, "%02hhx", &tmp); // NOTE THE FUCKING 'hh' VALUE ASS!  BUFFER OVERFLOWS OMG LOL!
    tstamp_buff[i] = tmp; // We'll need the buffer of the timestamp to recompute the MAC
    tstamp_o += ((unsigned int)tmp << (32-(i+1)*8));
  }
  fscanf(fin,"%c",&tmp); // Here we grab the line between the file size and timestamp

  tstamp_n = (unsigned)time(NULL);

  //  Check for potential replay attacks.
  if((tstamp_n - tstamp_o) > REPLAY_THRESH){
    fprintf(stderr, "ERROR: Replay Attack Detected.  Exiting.\n");
    exit(-1);
  }

  // Read in the RSA Pub Key
  privkey = PEM_read_RSAPrivateKey(privatekey_file, NULL, NULL, NULL);
  if(privkey == NULL){
    fprintf(stderr, "ERROR: Unable to read Private key!\n");
    exit(-1);
  }

  // Load the RSA ciphertext data
  for(i = 0; i < rsa_key_bytes; i++)
    fscanf(fin,"%02hhx",&rsa_ciphertext_buff[i]);
  fscanf(fin,"%c",&tmp); // Here we grab the line between the RSA Ciphertext and Sym IV

  // Load the symmetric key iv
  for(i = 0; i < sym_key_bytes; i++)
    fscanf(fin,"%02hhx",&symmetric_iv[i]);
  fscanf(fin,"%c",&tmp); // Here we grab the line between the Sym IV Sym Ciphertext

  // Allocate memory to store the cipher text
  sym_ciphertext_buff = malloc(f_size + pad + sym_key_bytes);
  if(sym_ciphertext_buff == NULL){
    fprintf(stderr, "ERROR: Unable to allocate memory for symmetric ciphertext!\n");
    exit(-1);
  }
  memset(sym_ciphertext_buff,0x0,(f_size + pad + sym_key_bytes));

  // Load the symmetric ciphertext data
  for(i = 0; i < (f_size + pad); i++)
    fscanf(fin,"%02hhx",&sym_ciphertext_buff[i]);
  fscanf(fin,"%c",&tmp); // Here we grab the line between the SHA_Key and the timestamp

  // Load the MAC
  for(i = 0; i < sha_key_bytes; i++)
    fscanf(fin,"%02hhx",&sha_buff_o[i]);

  if(timed)
    start = clock();

  // Decrypt the RSA Encrypted data
  ret = RSA_private_decrypt(rsa_key_bytes, rsa_ciphertext_buff, rsa_cleartext_buff, 
                                privkey, RSA_PKCS1_OAEP_PADDING);

  if(timed)
    asym = clock();

  // Copy the the Symmetric Key into its buffer
  for(i = 0; i < sym_key_bytes; i++)
    symmetric_key[i] = rsa_cleartext_buff[i];

  // Copy the the MAC Key into its buffer
  for(i = 0; i < sha_key_bytes; i++)
    sha_key[i] = rsa_cleartext_buff[sym_key_bytes+i];

  // Copy the timestamp into the cipher text
  for(i = 0; i < 4; i++)
    sym_ciphertext_buff[f_size + pad + i] = tstamp_buff[i];

  // Compute a new digest and check the integrity of the data
  sha_buff_n = HMAC(EVP_sha256(), sha_key, sha_key_bytes, sym_ciphertext_buff, 
                        (f_size + pad + sym_key_bytes), NULL, NULL);

  if(sha_buff_n == NULL){
    fprintf(stderr, "ERROR: An error occured computing the new message digest!\n");
    exit(-1);
  }

  for(i = 0; i < sha_key_bytes; i++){
    if(sha_buff_n[i] != sha_buff_o[i]){
      fprintf(stderr, "ERROR: MAC Does not match!  Integrity Compromised!!\n");
      exit(-1);
    }
  }

  if(timed)
    hmac = clock();

  // Set the AES Decryption Key to the Key that was imported from key.txt
  AES_set_decrypt_key(symmetric_key, SYM_KEY_BITS, &aes_key);

  // Allocate memory to store the clear text
  sym_cleartext_buff = malloc(f_size + pad);
  if(sym_cleartext_buff == NULL){
    fprintf(stderr, "Unable to allocate memory for writing!\n");
    exit(1);
  }
  memset(sym_cleartext_buff, 0x0, (f_size + pad));

  // Perform Decryption
  AES_cbc_encrypt(sym_ciphertext_buff, sym_cleartext_buff, (f_size + pad), &aes_key, symmetric_iv, AES_DECRYPT);

  if(timed)
    stop = clock();

  // Print the size of the file to start of the decoded plaintext file
  fprintf(fout,"%u\n",(f_size*2));

  // Print the cleartext to the decrypted plaintext file
  for(i = 0; i < f_size; i++)
    fprintf(fout,"%02x",sym_cleartext_buff[i]);
  
  //Print out timing information
  //Print out timing information
  if(timed){
    printf("Total: %f", ((double)(stop - start)/CLOCKS_PER_SEC));
    printf(" Sym: %f", ((double)(stop - hmac)/CLOCKS_PER_SEC));
    printf(" Asym: %f", ((double)(asym - start)/CLOCKS_PER_SEC));
    printf(" HMAC: %f\n", ((double)(hmac - asym)/CLOCKS_PER_SEC));
  }

  // Close our opened files.
  fclose(fin);
  fclose(fout);
  fclose(urand);
  fclose(publickey_file);
  fclose(privatekey_file);

  // Free heap allocated memory
  free(sym_ciphertext_buff);
  free(sym_cleartext_buff);

  // Finished Rummimg Decryption
  return 1;
}
