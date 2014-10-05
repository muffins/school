
/* 
 * Nick Anderson, 04/27/2014
 *
 * hybridpublickeygen.c
 * 
 * Key generation program for Modern Cryptography - Final Project, Part 3
 * 
 * Description: This code generates the public key for the RSA asymmetric
 * cryptographic scheme.
 * 
 * Usage:
 *    $ ./hybridpublickeygen
 * 
 */

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// RSA key size is in bits
#define RSA_KEY_SIZE 2048
#define PUB_EXPONENT 65537

int main(int argc, char* argv[]){
  
  // Local Variable definitions
  int i, j, k;
  size_t ret;
  int rsa_byte_size = RSA_KEY_SIZE/8;

  // buffer used to seed the PRNG
  unsigned char seed[rsa_byte_size];
  //unsigned char *keybuff;
  unsigned char *priv;
  unsigned char *pub;
  unsigned char *mod;
  size_t keybuff_len=0;

  // File pointers
  FILE *urand;
  FILE *pubkeyfile;
  FILE *privkeyfile;

  // RSA Struct used to store Priv/Pub key vals
  RSA *key = RSA_new();

  // Set the exponent size, e, to be used by RSA.
  BIGNUM *e = BN_new();

  // Open the public keyfile
  pubkeyfile = fopen("./publickey.txt","w+");
  if(pubkeyfile == NULL){
      fprintf(stderr, "ERROR: Unable to open publickey.txt for writing!\n");
      exit(-1);
  }

  // Open the private keyfile
  privkeyfile = fopen("./secretkey.txt","w+");
  if(privkeyfile == NULL){
      fprintf(stderr, "ERROR: Unable to open privatekey.txt for writing!\n");
      exit(-1);
  }

  // Open dev rand to seed our random data.
  urand = fopen("/dev/urandom","r");
  if(urand == NULL){
      fprintf(stderr, "ERROR: Unable to open /dev/urandom for reading!\n");
      exit(-1);
  }

  // Read the rand data from /dev/urandom
  ret = fread(&seed, sizeof(char), RSA_KEY_SIZE/8, urand);
  if(ret < RSA_KEY_SIZE/8){
      fprintf(stderr, "ERROR: Unable to obtain random seed from /dev/urandom!\n");
      exit(-1);
  }
  
  // Seed the PRNG
  RAND_seed(&seed, RSA_KEY_SIZE/8);

  // Setup our BIGNUM, this acts as the exponent e and will be stored with the pub/priv keys struct
  // read the BN_rand description to see why the last two args are 1.
  //ret = BN_generate_prime_ex(e, RSA_KEY_SIZE, 1, NULL, NULL, NULL);
  ret = BN_set_word(e, 0x10001); // 65537
  if(!ret){
    fprintf(stderr, "ERROR: There was a problem generating the mod 'e'\n");
    exit(-1);
  }


  // NOTE: As per the OpenSSL docs, RSA_generate_key(...) is deprecated.
  // int RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);
  // Generate the RSA keys
  ret = RSA_generate_key_ex(key, RSA_KEY_SIZE, e, NULL);

  /* Currently, the OpenSSL doc does not detail the return value of RSA_generate_key_ex :-( */
  if(!ret){
    fprintf(stderr, "ERROR: There was a problem generating RSA key!\n");
    exit(-1);
  }

/*
  printf("DBG: Public Key - ");
  char * n_val = BN_bn2hex(key->n);
  for(i = 0; i < 256; i++){
    printf("%c", n_val[i]);
  }
  printf("\n");
*/


  if(!PEM_write_RSAPublicKey(pubkeyfile, key)){
    fprintf(stderr, "ERROR: There was a problem writing the Public RSA key!\n");
    exit(-1);
  }
  if(!PEM_write_RSAPrivateKey(privkeyfile, key, NULL, NULL, 0, NULL, NULL)){
    fprintf(stderr, "ERROR: There was a problem writing the Private RSA key!\n");
    exit(-1);
  }

/*
  // Write the public and private key values out to disk respectively
  //i = BN_num_bytes(key->e);
  //j = BN_num_bits(key->e);
  //keybuff = BN_bn2hex(key->e);
  priv = BN_bn2hex(key->d);
  pub  = BN_bn2hex(key->e);
  mod  = BN_bn2hex(key->n);

  // Write out the public modulus, n
  j = BN_num_bytes(key->e);
  for(i = 0; i < j; i++){
    fprintf(pubkeyfile, "%c", mod[i]);
    fprintf(privkeyfile, "%c", mod[i]);
  }
  fprintf(pubkeyfile,"\n");
  fprintf(privkeyfile,"\n");

  // Write out the public key
  j = BN_num_bytes(key->e);
  for(i = 0; i < j; i++){
    fprintf(pubkeyfile, "%c", pub[i]);
  }

  // Write out the private key
  j = BN_num_bytes(key->d);
  for(i = 0; i < j; i++){
    fprintf(privkeyfile, "%c", priv[i]);
  }
*/

  //printf("DBG: Number of bytes in e - %d\n", i);
  //DBG: Number of bytes in e - 256
  //printf("DBG: Number of bits in e - %d\n", j);
  //DBG: Number of bits in e - 2048

  /*
  printf("DBG: Print e:\n");
  for(k = 0; k < i; k++){
    printf("%c",keybuff[k]);
  }
  printf("\nDone.\n");

  // Note, the below is 256 characters, or 2048 bits worth of data.

  DBG: Print e:
  DF61CD9DCFF8B60F8302098EEA099F1B9ECED5C5AD3C98E129D380121A765BE089D6FAFEBACF272B5A87FC98995
  A259D6F9D069805436F0B93AFBB02ABAD2C19DD767F25DC25226DA99B24C92727A0F583FE8CAD4C60702A1F4EDB
  7F8E3A872519A8515DCBB963E676939FDCC2DFFD40C970137952FADB5048F7DAB4632646C8
  Done.

  */


  // Free allocated memory
  fclose(urand);
  fclose(pubkeyfile);
  fclose(privkeyfile);

  // Free the allocated RSA structures.
  RSA_free(key);
  BN_free(e);

  return 1;
}
