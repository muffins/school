////////////////////////////////////////////////////////////////////////////////
// AES CBC Key Generation
// Modern Cryptography Project Part 2
// Description: This code generates a key for the AES CBC Encryption Scheme.
// scheme. Running this program will create a random value of 128-bits that
// is used as the key for the block cipher. The result will be key.txt.
// Usage:
//       ./keygen
////////////////////////////////////////////////////////////////////////////////
#include <stdio.h>
#include <stdlib.h>
#include <time.h>


int main(int argc, char* argv[]){
  // Creat variable for the file
  FILE *keyfile;
  // Open the file
  keyfile = fopen("key.txt","w+");
  if(keyfile == NULL){
    fprintf(stderr, "Unable to open key.txt for writing\n");
    exit(1);
  }
  
  // Seed random with the time
  srand ( time(NULL) );
  // Create integers to hold 128 bits of data
  unsigned int num1,num2,num3,num4;
  // Load the integers with random values
  num1 = rand();
  num2 = rand();
  num3 = rand();
  num4 = rand();
  //Print the random values to a file
  fprintf(keyfile,"%08x%08x%08x%08x", num1,num2,num3,num4);
  fclose(keyfile);
  return 1;
}
