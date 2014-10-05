#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include <stdio.h>
#include <string.h>
#include "ctrhdr.h"


void usage ( void ) {
    fprintf ( stderr, "\n\nUsage: ./keygen keytype\n");
    fprintf ( stderr, "Example invocation:\n");
    fprintf ( stderr, "                      ./keygen sha256\n" );
    fprintf ( stderr, "\n" );
    fprintf ( stderr, "Available keytypes are: md5, sha1, sha224, sha256, sha384, sha512, aes128\n");
    fprintf ( stderr, "\n");
    fprintf ( stderr, "Program output may be redirected from stdout using the > symbol\n" );
    fprintf ( stderr, "\n" );
}



int main(int argc, char* argv[]){

    /* file to write key to */
    FILE          *key_file;

    /* key generated from random bytes */
    unsigned char key [ MAX_KEY_SIZE ];
    
    /* argument for processing key type in program invocation line */
    struct encode_arg   arg;
    
    /* returned attributes for key type */
    struct encode_attr  key_attrib;
    
    int status;

    /* there should only be one argument, a literal specifying the key type */
 
    if ( argc != 2 ) {
        usage();
        exit(1);
    }
 
    /* copy the string argument and pass it for parsing */
    
    arg.type = LIT;
    strcpy( arg.arg.str, argv[1] );
    
    status = get_encode_attr ( stderr, 0, &arg, &key_attrib );
    if ( status ){
        usage();
        exit(1);
    }
    
    /* ensure returned keysize does not exceed maximum.  using fixed size to avoid buffer allocation */
    
    if ( key_attrib.default_keysize > MAX_KEY_SIZE ) {
        fprintf( stderr, "Internal Error - Keysize Exceeds Maximum\n" );
        exit (1);
    }
    
    if ( !RAND_bytes( key, key_attrib.default_keysize ) ) {
        fprintf(stderr, "Failed To Generate Key\n");
        exit (1);
    }
    
    /* Write out key to key file */
    
    key_file = stdout;
    
    int i=0;

    while ( i < key_attrib.default_keysize ) {
        fprintf( key_file, "%02x", key[i++]);
    }

    /* write newline.  cleaner if stdout not redirected and data being printed on screen */
    fprintf( key_file, "\n" );

    return 0;
}
