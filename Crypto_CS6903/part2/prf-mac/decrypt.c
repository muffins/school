////////////////////////////////////////////////////////////////////////////////
// AES CBC Decryption
// Modern Cryptography Project Part 2
// Description: This code preforms decryption using the AES CBC.
// scheme. The data to be decrypted is input in a file of the following form:
//         -Line 1: Number of characters of data in the file
//         -Line 2: Initial Value in hex representation (A is 41, B is 42, etc.)
//         -Line 3: Encrypted Data in hex representation(A is 41, B is 42, etc.)
// The output from running decryption is of the following form:
//         -Line 1: Number of characters of data in the file
//         -Line 2: Data in hex representation (A is 41, B is 42, etc.)
// During encryption the incoming data was padded so that it alines with a 
// block boundary, the data padding is not added to the number of characters
// shown on line 1 of the ciphertext file.
// Usage:
//       ./decrypt <key_filename> <ciphertext_filename> [-t]
// The use of -t will time the operation of the encryption, which does not
// include the associated file IO for loading the key initial value or the data.
// Note that the time is always calculated the flag determines if the time is
// printed. Key_filename and plaintext.hex_filename must be supplied to print
// the timing however if timing isn't desired then the default names for the
// key_filename and plaintext.hex_filename are key.txt and plaintext.txt
// repectively.
////////////////////////////////////////////////////////////////////////////////
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/aes.h>

#define REPLAY_THRESH 120


int main(int argc, char* argv[]){
  // Create Timing Variables
  //struct timespec tstart={0,0}, tend={0,0};
  clock_t start, stop, tag_time, tag_verify;

  // File size and pad variable
  int f_size, pad;

  // Loop Variables, temporary place holder values.
  int i, j, new_line_val, timed = 0;

  // Buffer for the aes key
  unsigned char key_in[18];

  // variable to store the length of the file, plus the pad
  size_t inputslength;
  
  // Create Variables for holding the key_filename and ciphertext_filename
  char *key_name, *ciphertext;

  // Part 2 Local Variables
  unsigned char hmac_key[AES_BLOCK_SIZE]; // buffer for HMAC AES key
  unsigned char *enc_buff; // intput buffer for enc text
  unsigned char *clear_buff; // output buff for cleartext
  unsigned char *hmac_buff; // buffer for the hmac memory
  unsigned char *dec_out; // buffer for the decrypted text
  unsigned char *plc_holder; // Place holder
  unsigned char tstamp_buff[4]; // buffer to holde the timestamp
  unsigned char hmac_iv[AES_BLOCK_SIZE]; // HMAC IV, set to null later.
  unsigned char seed[64]; // Random seed buffer
  unsigned char tmp=0x0; // Place holder
  unsigned int tstamp_o=0, tstamp_n=0, ret=0; // timestamp and return placeholders.
  long origin=0; // Used to holder place in fseek func calls.
  
  AES_KEY hmac_enc_key;
  AES_KEY key;
  FILE *hmac_key_file;
  FILE *keyfile;
  FILE *data;
  FILE *pt;

  


  // Load the command line arguments
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
  // If no file names are specified then we load default file names
  else {
    // Using Default key and ciphertext file names
    key_name = "key.txt";
    ciphertext = "ciphertext.txt";
  }

  // Load the Key from the key file
  keyfile = fopen(key_name,"r");
  if(keyfile == NULL){
    fprintf(stderr, "File '%s' needed to preform encryption - run keygen first\n",key_name);
    exit(1);
  }
  
  for(i=0;i<16;i++){
    fscanf(keyfile,"%02hhx",&key_in[i]);
  }
  
  // Set the AES Decryption Key to the Key that was imported from key.txt
  //int AES_set_decrypt_key(const unsigned char *userKey,
  //                        const int bits,
  //	                  AES_KEY *key);
  AES_set_decrypt_key(key_in, 128, &key);

  
  // Open the Ciphertext file
  data = fopen(ciphertext,"r");
  if(data == NULL){
    fprintf(stderr, "File '%s' not found... Please provide data to encrypt.\n",ciphertext);
    exit(1);
  }

  // Load FileSize
  
  fscanf(data,"%i\n",&f_size);
  
  // Load Initialization Vector
  unsigned char iv_dec[AES_BLOCK_SIZE];
  memset(iv_dec, 0x0, AES_BLOCK_SIZE);
  
  for(i=0;i<AES_BLOCK_SIZE;i++){
    fscanf(data,"%02hhx",&tmp);
    iv_dec[i] = tmp;
  }
  fscanf(data,"%c",&tmp); // Throw out the newline.

 /*

    A POKE-CHALLENGER APPEARS!

    The most awesome bro-grammer on the block, thinks that your
    data may not be integrituitous.  Let's compute a motha-fuckin HMAC
    and ensure that yo shit is solid brah.

  */

  // First we need to read in that most secksy of timestamps.
  // The below line is kinda dangerous, but I live dangerously, so w/e.
  // essentially we're relying on the above fscanf's to work correctly :P
  // they might already, but.... I don't know that.
  

    /* Record the current filestream location */
  origin = ftell(data);

  /* Compute the pad.  Note that this is only used for the seek and will be recomputed later */
  pad = 32-(f_size%32);

  /* Clear the buffer used for the timestamp */
  memset(tstamp_buff, 0x0, 4);

  /* Get the timestamp, and check it's 'freshness' before we do anything. */
  if(fseek(data, (f_size+pad), SEEK_CUR) != 0){
    fprintf(stderr, "Unable to seek through ciphertext to timestamp!\n");
    exit(1);
  }

  /* Grab the timestamp from the cipher text file.  This should exist on Line 4 */
  for(i = 0; i < 4; i++){
    fscanf(data, "%02hhx", &tmp);  // NOTE THE FUCKING 'hh' VALUE ASS!  BUFFER OVERFLOWS OMG LOL!
    tstamp_buff[i] = tmp; // We'll need the buffer of the timestamp to recompute the MAC
    tstamp_o += ((unsigned int)tmp << (32-(i+1)*8));
  }

  /* Go get the current time, to show that poke-challenger that he's a poke-loser. */
  tstamp_n = (unsigned)time(NULL);
  if((tstamp_n - tstamp_o) > REPLAY_THRESH){
    fprintf(stderr, "Replay Attack Detected.  Exiting.\n");
    exit(1);
  }

  /* Seek back to the beginning of the cipher text */
  if(fseek(data, origin, SEEK_SET) != 0){
    fprintf(stderr, "Unable to seek to beginning of ciphertext!\n");
    exit(1);
  }

  // Calculate the PAD used on the data and load the data.
  f_size = f_size/2;
  pad = 16-(f_size%16);
  inputslength = f_size+pad;

  // Allocate memory to store the cipher text
  enc_buff = malloc(f_size+pad+AES_BLOCK_SIZE);
  memset(enc_buff, 0x0, (f_size+pad+AES_BLOCK_SIZE));

  // Allocate memory for the output buffer.
  hmac_buff = malloc(f_size+pad+AES_BLOCK_SIZE);
  memset(hmac_buff, 0x0, (f_size+pad+AES_BLOCK_SIZE));

  if(enc_buff == NULL){
    fprintf(stderr, "Unable to allocate memory for cipher text readin!\n");
    exit(1);
  }
  if(hmac_buff == NULL){
    fprintf(stderr, "Unable to allocate memory for HMAC buffer!\n");
    exit(1);
  }
  /* If my math is right, and it sometimes is, this should grab explicitly the cipher text data */
  for(i = 0; i < (f_size+pad); i++)
    fscanf(data,"%02hhx",&enc_buff[i]);

  /* Copy the Timestamp onto the cipher text. */

  for(i = 0; i < 4; i++)
    enc_buff[f_size+pad+1+i] = tstamp_buff[i];

  /* Stage the HMAC Key */
  memset(hmac_key, 0x0, AES_BLOCK_SIZE);

  /* Go and fetch yon HMAC Key */
  hmac_key_file = fopen("hmac_key.txt", "r");
  for(i = 0; i < 16; i++)
    fscanf(hmac_key_file, "%02hhx", &hmac_key[i]);

  if(AES_set_encrypt_key(hmac_key, AES_BLOCK_SIZE*8, &hmac_enc_key) != 0){
    fprintf(stderr, "Unable to set the AES encryption key!\n");
    exit(1);
  }

  /* In our case for the HMAC the IV is 0. */
  memset(hmac_iv, 0x0, AES_BLOCK_SIZE);

  /* Compute the Tag computation time, and general start time */
  if(timed)
    start = clock();

  /* Re-compute the encryption, as we need to verify that the data recieved wasn't BULLSHIT! */
  AES_cbc_encrypt(enc_buff, hmac_buff, (inputslength + AES_BLOCK_SIZE), &hmac_enc_key, hmac_iv, AES_ENCRYPT);

  // Record the amount of time to compute the Tag
  if(timed)
    tag_time = clock();

  /*  
  Now that we've re-computed the Tag, we need to read in the HMAC data. Our best
  shot is to read in the data, check that it matches our computed tag.  There's no reason to store it. 
  */

  /*
    Seek ahead to our HMAC values.  The seek value here is 8,
    plus one for the newline
  */
  if(fseek(data, ( sizeof(int)*2+1 ), SEEK_CUR) != 0){
    fprintf(stderr, "Unable to seek to beginning of ciphertext!\n");
    exit(1);
  }

  
  for(i = 0; i < (f_size+pad+AES_BLOCK_SIZE); i++){
    fscanf(data,"%02hhx",&tmp); // read in the character
    if(tmp != hmac_buff[i]){
      fprintf(stderr, "Data corruption detected!  Exiting!\n");
      exit(1);
    }
  }

  // Record the time needed to verify the integrity of the data
  if(timed)
    tag_verify = clock();

  /* If you've made it this far, the Tag was correct and the data is good.  Free the Tag bufer */
  free(hmac_buff);

  plc_holder = realloc(enc_buff, f_size+pad);
  if(plc_holder == NULL){
    fprintf(stderr, "Unable to reallocate ciphertext buffer.\n");
    exit(1);
  } else {
    enc_buff = plc_holder;
  }


  /* If you make it to this point do the actual decryption and proceed as normal :P 
    Just make sure that the enc_buff is the correct size, or that we've realloc'd it
    before we continue >.> */


  // Decrypt the data.
  //void AES_cbc_encrypt(const unsigned char *in,
  //                     unsigned char *out,
  //                 size_t length,
  //                     const AES_KEY *key,
  //                 unsigned char *ivec,
  //                     const int enc);
  inputslength = f_size+pad;

  // Allocate memory to store the clear text
  dec_out = malloc(f_size+pad);
  memset(dec_out, 0x0, f_size+pad);
  if(dec_out == NULL){
    fprintf(stderr, "Unable to allocate memory for writing!\n");
    exit(1);
  }

  // Perform Decryption
  AES_cbc_encrypt(enc_buff, dec_out, inputslength, &key, iv_dec, AES_DECRYPT);

  // Finish Timing Here
  if(timed)
    stop = clock();


  // Write the Decrypted data to the Decrypted data file
  pt = fopen("decryptedplaintext.txt","w+");
  if(pt == NULL){
    fprintf(stderr, "File 'decryptedplaintext.txt' couldn't be opened or created... its your problem now\n");
    exit(1);
  }
  // Print the size of the file to start of the decoded plaintext file
  fprintf(pt,"%i\n",(f_size*2));
  for(i=0;i<f_size;i++){
    fprintf(pt,"%02x",dec_out[i]);
  }
  
  //Print out timing information
  if(timed)
    printf("Decryption: %f\tTag Verify: %f\tTag: %f\tTotal: %f\n", 
      ((double)(stop - tag_verify)/CLOCKS_PER_SEC), 
      ((double)(tag_verify - tag_time)/CLOCKS_PER_SEC), 
      ((double)(tag_time - start)/CLOCKS_PER_SEC), 
      ((double)(stop - start)/CLOCKS_PER_SEC));

  // Free heap allocated memory
  fclose(data);
  fclose(keyfile);
  fclose(pt);
  fclose(hmac_key_file);
  free(enc_buff);
  free(dec_out);

  // Finished Running Decryption
  return 1;
}
