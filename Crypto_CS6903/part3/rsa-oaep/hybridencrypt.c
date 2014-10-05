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
 * The program will output a 'ciphertext.txt' file with the following
 * format, all in hexadecimal characters
 *
 * Line 1: A single unsigned integer indicating the number of characters
 *         in the ciphertext
 * Line 2: The timestamp at which poin the symmetric encryption occured
 * Line 3: RSA Encrypted HMAC and Symmetric Keys
 * Line 4: Initialization vector for the Symmetric Key encryption
 * Line 5: Symmetric Key Encrypted cipher text of plaintext.txt
 * Line 6: SHA256 Digest of (Ciphertext | Timestamp), where '|' represents
 *         data concatenation.
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
#define RSA_KEY_BITS 2048
#define SYM_KEY_BITS 128 // AES Symmetric Key
#define SHA_KEY_BITS 256

// Function Declarations
//void print_err(int eid), eid isn't really used.
void print_err(int);


int main(int argc, char* argv[]){

  // Counter and placeholder variables
  int i, j, pad, sha_padding, ret, timed=0;
  unsigned char tmp=0x0;

  // Variable for how many characters are in the file.
  unsigned int f_size = 0;
  unsigned int tstamp = 0;
  size_t rsa_key_bytes = RSA_KEY_BITS/8;
  size_t sym_key_bytes = SYM_KEY_BITS/8;
  size_t sha_key_bytes = SHA_KEY_BITS/8;

  // Timing Variables
  clock_t start, stop, asym, sym, hmac;

  // Pointers to filenames
  unsigned char *cleartext_fname = NULL;
  unsigned char *publickey_fname = NULL;

  // RSA Clear and Cipher text buffers
  // We use RSA Pub Key to encrypt the sym key and the HMAC key
  // Plus 1 for a nulbyte from snprintf
  unsigned char rsa_cleartext_buff[sym_key_bytes+sha_key_bytes];
  // See OpenSSL RSA_Public_Encrypt for specification on ciphertext size
  unsigned char rsa_ciphertext_buff[rsa_key_bytes]; 

  // Symmetric Encryption Clear, Cipher, and Key Buffs
  unsigned char *sym_cleartext_buff = NULL;  
  unsigned char *sym_ciphertext_buff = NULL;
  unsigned char symmetric_key[sym_key_bytes];
  unsigned char symmetric_iv[sym_key_bytes];
  unsigned char sym_iv_tmp[sym_key_bytes]; // Because fuck OpenSSL.  That's why.

  // Allocate buffers for SHA MAC
  unsigned char *sha_buff = NULL;
  unsigned char sha_key[sha_key_bytes];

  // PRNG Seed buffer
  unsigned char seed[rsa_key_bytes];
  
  // File pointers
  FILE *publickeyfile;
  FILE *urand;
  FILE *fout;
  FILE *fin;

  // OpenSSL Structs
  RSA *pubkey = NULL;
  AES_KEY aes_key;

  memset(rsa_cleartext_buff, 0x0, (sym_key_bytes+sha_key_bytes));
  memset(rsa_ciphertext_buff, 0x0, rsa_key_bytes);
  memset(symmetric_key, 0x0, sym_key_bytes);
  memset(symmetric_iv, 0x0, sym_key_bytes);
  memset(sha_key, 0x0, sha_key_bytes);

  // Get the filenames from commandline
  if(argc != 1){
    if(argc != 3 && argc != 4){
      printf("Usage: %s publickey.txt plaintext.txt [-t]\n", argv[0]);
      exit(-1);
    } else if(argc == 4 && !strncmp(argv[3],"-t",2)){
      timed = 1;
    }
    // Lets get our file names to some buffers
    publickey_fname = argv[1];
    cleartext_fname = argv[2];
  } else {
    // Using Default key and plaintext file names
    publickey_fname = "publickey.txt";
    cleartext_fname = "plaintext.txt";
  }

  // Open the file for the Ciphertext
  fout = fopen("ciphertext.txt","w+");
  if(fout == NULL){
    fprintf(stderr, "ERROR: Unable to open 'ciphertext.txt' for writing!\n");
    exit(-1);
  }

  // Load the Data for Encryption  
  fin = fopen(cleartext_fname,"r");
  if(fin == NULL){
    fprintf(stderr, "ERROR: Unable to open '%s' for reading!\n",cleartext_fname);
    exit(-1);
  }

  // Load the public key file
  publickeyfile = fopen(publickey_fname,"r");
  if(publickeyfile == NULL){
    fprintf(stderr, "ERROR: File '%s' needed to preform encryption - run keygen first\n", publickey_fname);
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

  // Read in the RSA Pub Key
  pubkey = PEM_read_RSAPublicKey(publickeyfile, NULL, NULL, NULL);
  if(pubkey == NULL){
    fprintf(stderr, "ERROR: Unable to obtain random seed from /dev/urandom!\n");
    exit(-1);
  }

  // Read in the filesize of the cleartext data
  fscanf(fin,"%u\n",&f_size);
  if(f_size%2){
    fprintf(stderr, "ERROR: File size should be divisble by 2! Exiting.\n");
    exit(-1);
  }
  f_size /= 2;

  // Compute the additional padding needed to make the cleartext alligned
  pad = sym_key_bytes - (f_size % sym_key_bytes); // This will ensure we're 32 byte alligned

  // Allocate memory to store the clear text
  sym_cleartext_buff = malloc(f_size + pad);
  if(sym_cleartext_buff == NULL){
    fprintf(stderr, "ERROR: Unable to allocate memory for clear text buffer!\n");
    exit(-1);
  }
  memset(sym_cleartext_buff, 0x0, (f_size + pad));

  // Read in the cleartext data.
  for(i = 0; i < f_size; i++)
    fscanf(fin, "%02hhx", &sym_cleartext_buff[i]);

  // Pad the cleartext data to make it alligned to a number divisible by sym_key_bytes
  // We pad using data from the beginning of the buffer, for added randomness.
  for(i = 0; i < pad; i++)
    sym_cleartext_buff[f_size + i] = sym_cleartext_buff[i];

  // Allocate memory to store the symmetric key encrypted text
  sym_ciphertext_buff = malloc(f_size + pad + sym_key_bytes);
  if(sym_ciphertext_buff == NULL){
    fprintf(stderr, "ERROR: Unable to allocate memory for cipher text buffer!\n");
    exit(-1);
  }
  memset(sym_ciphertext_buff, 0x0, (f_size + pad + sym_key_bytes));

  // Start timing here
  if(timed)
    start = clock();

  // Generate a symmetric key
  if(!RAND_bytes(symmetric_key, sym_key_bytes)){
    fprintf(stderr, "ERROR: Unable to obtain random bytes from PRNG!\n");
    exit(-1);
  }

  // Generate an Initialization Vector for the sym key encryption
  if(!RAND_bytes(symmetric_iv, sym_key_bytes)){
    fprintf(stderr, "ERROR: Unable to obtain random bytes from PRNG!\n");
    exit(-1);
  }

  // Generate a key for the SHA MAC scheme
  if(!RAND_bytes(sha_key, sha_key_bytes)){
    fprintf(stderr, "ERROR: Unable to obtain random bytes for SHA Key!\n");
    exit(-1);
  }

  // Set the key, in our case we're using AES
  AES_set_encrypt_key(symmetric_key, SYM_KEY_BITS, &aes_key);

/*
  printf("DBG: Symmetric IV - ");
  for(i = 0; i < sym_key_bytes; i++)
    printf("%02x", symmetric_iv[i]);
  printf("\n");
*/

  // Go get our super great timestamp
  tstamp = (unsigned)time(NULL);


  /* OpenSSL Makes me want to set things on fire.  Below, we make
  a call to AES_cbc_encrypt, which for some fucking asinine reason
  overflows/overwrites the symmetric_iv buffer.  This means that if
  you don't hang onto this IV, or write it out immediately, you're 
  somewhat fucked.  Woo.  As such we make a spoof IV buffer, and hand
  that to OpenSSL to shit all over. */

  for(i = 0; i < sym_key_bytes; i++)
    sym_iv_tmp[i] = symmetric_iv[i];

  // Encrypt the clear text with the sym key encryption
  AES_cbc_encrypt(sym_cleartext_buff, sym_ciphertext_buff, (f_size + pad), &aes_key, sym_iv_tmp, AES_ENCRYPT);

  if(timed)
    sym = clock();

  // append the time stamp to the encrypted data.
  for(i = 0; i < 4; i++){
    unsigned char t = (tstamp >> (32 - (i+1)*8)) & 0xFF;
    sym_ciphertext_buff[f_size + pad + i] = t;
  }

  // Compute the MAC  
  sha_buff = HMAC(EVP_sha256(), sha_key, sha_key_bytes, sym_ciphertext_buff, 
                        (f_size + pad + sym_key_bytes), NULL, NULL);

  if(timed)
    hmac = clock();

  if(sha_buff == NULL){
    fprintf(stderr, "ERROR: Problem generating the MAC!\n");
    exit(-1);
  }


  // Now, encrypt the Symmetric Key and HMAC key using public key crypto

  // Copy the Sym Key into the RSA Clear Buff
  for(i = 0; i < sym_key_bytes; i++)
    rsa_cleartext_buff[i] = symmetric_key[i];

  // Copy the HMAC key into the RSA Clear Buff
  for(i = 0; i < sha_key_bytes; i++)
    rsa_cleartext_buff[sym_key_bytes+i] = sha_key[i];  

  // Encrypt the keys
  ret = RSA_public_encrypt((sym_key_bytes+sha_key_bytes), rsa_cleartext_buff, 
                        rsa_ciphertext_buff, pubkey, RSA_PKCS1_OAEP_PADDING);

  if(timed)
    asym = clock();

  // IF RSA Encrypt has any issues, print out the error message.
  if(ret <= 0){
    print_err(ret);
    exit(-1);
  }

  // Finish Timing Here
  if(timed)
    stop = clock();


  // Write everything out to ciphertext.txt

  // Write the size
  fprintf(fout, "%u\n", (f_size*2));

  // Write the timestamp to the file
  for(i = 0; i < 4; i++){
    unsigned char t = (tstamp >> (32 - (i+1)*8)) & 0xFF;
    fprintf(fout, "%02x", t);
  }
  fprintf(fout, "\n");

  // Write the Encrypted symmetric key and MAC key to the file
  for(i = 0; i < rsa_key_bytes; i++)
    fprintf(fout,"%02x",rsa_ciphertext_buff[i]);
  fprintf(fout,"\n");

  // Write the IV for the symmetric encryption to the file
  for(i = 0; i < sym_key_bytes; i++)
    fprintf(fout,"%02x",symmetric_iv[i]);
  fprintf(fout,"\n");

  // Write the Encrypted message to the ciphertext file
  for(i = 0; i < (f_size+pad); i++)
    fprintf(fout,"%02x",sym_ciphertext_buff[i]);
  fprintf(fout,"\n");

  // Write the MAC to the ciphertext file
  for(i = 0; i < sha_key_bytes; i++)
    fprintf(fout,"%02x",sha_buff[i]);
  fprintf(fout, "\n");

  //Print out timing information
  if(timed){
    printf("Total: %f", ((double)(stop - start)/CLOCKS_PER_SEC));
    printf(" Sym: %f", ((double)(sym - start)/CLOCKS_PER_SEC));
    printf(" Asym: %f", ((double)(asym - hmac)/CLOCKS_PER_SEC));
    printf(" HMAC: %f\n", ((double)(hmac - sym)/CLOCKS_PER_SEC));
  }

  // Close files
  fclose(fin);
  fclose(fout);
  fclose(urand);
  fclose(publickeyfile);

  // Free Heap allocated memory
  free(sym_ciphertext_buff);
  free(sym_cleartext_buff);
  RSA_free(pubkey);

  // Finished Rummimg Encryption
  return 1;
}

void print_err(int eid){
  char *err = malloc(130);
  ERR_load_crypto_strings();
  ERR_error_string(ERR_get_error(), err);
  fprintf(stderr, "ERROR: %s\n", err);
  free(err);
}