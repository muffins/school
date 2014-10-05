#include <stdio.h>
#include <stdlib.h>
#include <time.h>


int main(int argc, char* argv[]){
  FILE *keyfile;
  keyfile = fopen("key.txt","w+");
  if(keyfile == NULL){
    fprintf(stderr, "Unable to open key.txt for writing\n");
    exit(1);
  }
  
  srand ( time(NULL) );
  unsigned int num1,num2,num3,num4;
  num1 = rand();
  num2 = rand();
  num3 = rand();
  num4 = rand();
  fprintf(keyfile,"%08x%08x%08x%08x", num1,num2,num3,num4);
  return 1;
}
