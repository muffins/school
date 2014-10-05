////////////////////////////////////////////////////////////////////////////////
// AES CBC Encryption
// Modern Cryptography Project Part 2
// Description: This code preforms encryption using the AES CBC.
// scheme. The data to be encrypted is input in a file of the following form:
//         -Line 1: Number of characters of data in the file
//         -Line 2: Data in hex representation (A is 41, B is 42, etc.)
// The output from running encryption is of the following form:
//         -Line 1: Number of characters of data in the file
//         -Line 2: Initial Value in hex representation (A is 41, B is 42, etc.)
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
#include <string.h>
#include <openssl/aes.h>

// We use a 128 bit AES key, 128/8 = 16, YAY MATH!

int main(int argc, char* argv[]){
  // Seed Random with time
  srand (time(NULL));

  // Create Timing Variables
  //struct timespec tstart={0,0}, tend={0,0}, tot={0,0};
  clock_t start, stop, enc_time;

  // Part 2 local variables.
  unsigned char hmac_key[AES_BLOCK_SIZE];
  unsigned int tstamp, ret;
  unsigned char* tstamp_buff[4];
  unsigned char seed[64];
  AES_KEY hmac_enc_key;
  FILE *hmac_key_file;
  FILE *keyfile;
  FILE *urand;
  FILE *ct;
  



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
  
  // Create an AES Key
  AES_KEY key;
  
  // Set the AES Encryption Key to the Key that was imported from key.txt
  //int AES_set_encrypt_key(const unsigned char *userKey,
  //                        const int bits,
  //	                  AES_KEY *key);
  AES_set_encrypt_key(key_in, 128, &key);
  
  // Open the file for the Ciphertext
  
  ct = fopen("ciphertext.txt","w+");
  if(ct == NULL){
    fprintf(stderr, "File 'ciphertext.txt' couldn't be opened or created... its your problem now\n");
    exit(1);
  }
  
  // Set Initialization Vector
  unsigned char iv_enc[AES_BLOCK_SIZE];
  memset(iv_enc, 0x0, AES_BLOCK_SIZE);
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
  data_in = malloc(f_size+pad);
  memset(data_in, 0x0, f_size+pad);
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
  
  // Print the size of the file to start of the cipher text file
  fprintf(ct,"%i\n",(f_size*2));

  // Print initialization vector to file
  for(i=0;i<AES_BLOCK_SIZE;i++){
    fprintf(ct,"%02x",iv_enc[i]);
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
  unsigned char *hmac;

  // Allocate memory to store the encrypted text
  enc_out = malloc(f_size+pad);
  memset(enc_out, 0x0, (f_size+pad));
  if(enc_out == NULL){
    fprintf(stderr, "Unable to allocate memory for writing!\n");
    exit(1);
  }

  // Start timing here
  if(timed)
    start = clock();

  // Perform Encryption
  AES_cbc_encrypt(data_in, enc_out, inputslength, &key, iv_enc, AES_ENCRYPT);

  // Get the Encryption timing
  if(timed)
    enc_time = clock();


  /* PART 2:
    
    Here we implement the HMAC Scheme.  In this specific implementation
    we generate the cipher text, retrieve a timestamp, which in this case
    is the Unix Time since Epoch, and append this timestamp to the end
    of the cipher text.  We then run the ciphertext|ts through the AES
    encryption scheme again, and utilize this newly generated cipher text
    for the MAC.  The data written out to the fill is then (Cipher Text, TS, HMAC)

  */

  // Data in is no longer needed, so lets free it to save a little memory...
  free(data_in);

  unsigned char * plce_holder;
  plce_holder = realloc(enc_out, (f_size+pad+AES_BLOCK_SIZE));
  if(plce_holder == NULL){
    fprintf(stderr, "Unable to reallocate ciphertext buffer.\n");
    exit(1);
  } else {
    enc_out = plce_holder;
  }

  /* Zero out the realloc data */
  for(i = 0; i < AES_BLOCK_SIZE; i++)
    enc_out[f_size+pad+i] = 0x0;

  // Allocate memory for the HMAC
  hmac = malloc(f_size+pad+AES_BLOCK_SIZE);
  memset(hmac, 0x0, (f_size+pad+AES_BLOCK_SIZE));

  // Seed PRNG
  urand = fopen("/dev/urandom", "r");
  if(urand == NULL){
    fprintf(stderr, "Unable to open key.txt for reading\n");
    exit(1);
  }
  ret = fread(&seed, 8, 8, urand);
  if(ret < 8){
    fprintf(stderr, "Unable to obtain random seed from /dev/urandom\n");
    exit(1);
  }
  
  // Perform the Actual PRNG seeding.
  RAND_seed(&seed, AES_BLOCK_SIZE);
  
  // Stage the HMAC Key
  memset(hmac_key, 0x0, AES_BLOCK_SIZE);
  
  // In our case for the HMAC the IV is 0.
  memset(iv_enc, 0x0, AES_BLOCK_SIZE);
  
  // Go get our super great timestamp
  tstamp = (unsigned)time(NULL);

  for(i = 0; i < 4; i++)
    enc_out[f_size+pad+1+i] = (tstamp >> (32 - (i+1)*8)) & 0xFF;


  // Set up the hmac key.  To do this we grab random bytes from OpenSSL's PRNG,
  // and hand this to the AES_set_encrypt_key function
  if(!RAND_bytes(hmac_key,AES_BLOCK_SIZE)){
    fprintf(stderr, "Unable to obtain random bytes from PRNG!\n");
    exit(1);
  }

  if(AES_set_encrypt_key(hmac_key, AES_BLOCK_SIZE*8, &hmac_enc_key) != 0){
    fprintf(stderr, "Unable to set the AES encryption key!\n");
    exit(1);
  }

  // We now have our Cipher Text + Timestamp, so lets run it through the encryption
  // algorithm one more time...
  // NOTE: The iv_enc has been zeroed out, as we use a Zero IV for the Tag.
  AES_cbc_encrypt(enc_out, hmac, (inputslength+AES_BLOCK_SIZE), &hmac_enc_key, iv_enc, AES_ENCRYPT);

  // Probably stop the timing here, as we don't care too much to time disk I/O <(^.^)>
  if(timed)
    stop = clock();



  // Proceed with the original AES encryption routine, mostly...

  // Write the Encrypted data to the Encrypted data file
  for(i = 0; i < (f_size+pad); i++){
    fprintf(ct,"%02x",enc_out[i]);
  }
  fprintf(ct,"\n");

  // Write the Time Stamp out to the file
  for(i = 0; i < 4; i++){
    unsigned char t = enc_out[f_size+pad+1+i] = (tstamp >> (32 - (i+1)*8)) & 0xFF;
    fprintf(ct,"%02x", t);
  }
  fprintf(ct,"\n");
  
  // Write the HMAC out to the file
  for(i = 0; i < (f_size+pad+AES_BLOCK_SIZE); i++)
    fprintf(ct,"%02x",hmac[i]);

  

  //Print out timing information
  if(timed){
        stop = clock();
        printf("Encryption: %f\tTag: %f\tTotal: %f\n", 
          ((double)(enc_time - start)/CLOCKS_PER_SEC), 
          ((double)(stop - enc_time)/CLOCKS_PER_SEC), 
          ((double)(stop - start)/CLOCKS_PER_SEC));
  }


  // Write the key used for the HMAC out to the disk.
  hmac_key_file = fopen("hmac_key.txt","w");
  unsigned char * buff = (unsigned char*) &hmac_enc_key;
  for(i = 0; i < AES_BLOCK_SIZE; i++)
    fprintf(hmac_key_file, "%02x", buff[i]);

  // Free Heap allocated memory
  fclose(hmac_key_file);
  fclose(urand);
  fclose(ct);
  fclose(data);
  fclose(keyfile);
  free(hmac);
  free(enc_out);
  

  // Finished Rummimg Encryption
  return 1;
}