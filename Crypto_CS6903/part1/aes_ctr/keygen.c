#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include <stdio.h>


void usage ( void ) {
    fprintf ( stderr, "\n\nUsage: ./keygen\n");
    fprintf ( stderr, "Example invocation:\n");
    fprintf ( stderr, "                      ./keygen\n" );
    fprintf ( stderr, "\n" );
    fprintf ( stderr, "Program output may be redirected from stdout using the > symbol\n" );
    fprintf ( stderr, "\n" );
}



int main(int argc, char* argv[]){
    FILE          *key_file;
    unsigned char key [AES_BLOCK_SIZE];

    /* check  arguments for validity */
    
    if ( argc >= 2 ) {
        /* should have only 1 argument, error */
        usage();
        exit (1);
    }

    /* generate key */
    
    if ( !RAND_bytes( key, AES_BLOCK_SIZE )) {
        fprintf(stderr, "Failed To Generate Key\n");
    }
    
    /* Write out key to key file */
    
    key_file = stdout;
    
    int i=0;

    while (i < AES_BLOCK_SIZE) {
        fprintf( key_file, "%02x", key[i++]);
    }

    /* write newline.  cleaner if stdout not redirected and data being printed on screen */
    fprintf( key_file, "\n" );
    
    fclose( key_file );

    return 0;
}
