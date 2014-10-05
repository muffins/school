//
//  encrypt.c
//  
//
//  Created by Dennis Mirante on 3/29/14.
//
//

#include <openssl/aes.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "ctrhdr.h"


void usage ( void ) {
    fprintf ( stderr, "\n\nUsage: ./encrypt key plaintext {-t}\n");
    fprintf ( stderr, "where:\n" );
    fprintf ( stderr, "       key is the file containing the 128 Bit AES KEY in hex format generated by keygen\n" );
    fprintf ( stderr, "       plaintext is the file containing plaintext data\n" );
    fprintf ( stderr, "       -t is an optional parameter that causes the display of collected timing statistics\n" );
    fprintf ( stderr, "\n" );
    fprintf ( stderr, "Example invocations:\n");
    fprintf ( stderr, "                      ./encrypt key plaintext\n" );
    fprintf ( stderr, "                      ./encrypt key plaintext -t\n" );
    fprintf ( stderr, "\n" );
    fprintf ( stderr, "Program output may be redirected from stdout using the > symbol\n" );
    fprintf ( stderr, "\n" );
}


// get hex input character by character from file to build 16 byte AES block
// buf points to 16 byte AES block buffer, len will be set with number of bytes converted

int getAESinput ( FILE * file,  unsigned char *buf, int *len ) {
    
    int chr;
    
    unsigned char * ptr = buf;
    
    /* Hex string for conversion will be built here. */
    char hex_inp [AES_BLOCK_SIZE * 2 + 1];
    
    char * hex_inp_ptr;
    
    int hex_str_len;
    
    hex_str_len = 0;
    
    /* initialize number of converted bytes to 0 */
    *len = 0;
    
    /* build hex input string for conversion */
    
    /* this loop reads hex character data from the file until either EOF is encountered
       or a hex data buffer to be converted to an AES block has been filled (32 characters).
     */
     
    while ( hex_str_len < AES_BLOCK_SIZE * 2 ) {

        chr = fgetc( file );
        
        /* quit if file is exhausted */
        
        if ( chr == EOF ) break;
        
        /* ignore all characters other than hex chars 0-9, a-f, A-F */
        
        if ( ( chr >= '0' && chr <= '9') || ( chr  >= 'A' && chr <= 'F' ) || (chr >= 'a' && chr <= 'f') ){
            
            /* store char in hex data buffer being built and bump the pointer */
            
            hex_inp[ hex_str_len ] = (char) chr;
            hex_str_len++;
        }
    }
    
    
    if ( hex_str_len == 0 ) {
        /* nothing found, return with normal status */
        return 0;
    }
    else if ( hex_str_len % 2 ){
        /* file is exhausted, uneven number of characters found, return error status */
        return 1;
    }
    else {
        /* terminate hex characters in buffer just built with null so its content can be processed as string */
        hex_inp[ hex_str_len ] = '\0';
    }
    
    /* set pointer to beginning of string data just collected */
    hex_inp_ptr = &hex_inp[0];
    
//    fprintf( stderr, " hex input = %s\n", hex_inp );
    
    /* convert all characters in hex string to byte values and store in AES block */
    
    while ( sscanf( hex_inp_ptr, "%02x", &chr ) == 1 ) {
        hex_inp_ptr = hex_inp_ptr + 2;
//        fprintf( stderr, "char = %d\n", chr );
        (*len)++;
        *ptr = ( unsigned char ) chr;
        ptr++;
    }
    
    /* return with number of hex data byes converted in *len and converted data in AES block */
    
    return 0;
    
}


/* 
   routine to initialze struture utilized by AES routines.  structure contains
   initialization vector and state variables maintained by AES routines.
 */

void init_ctr ( AES_CTR_STATE *ctr_state, unsigned char iv [AES_BLOCK_SIZE] ) {
    
    /* clear the ctr_state structure */
    memset( ctr_state, 0, sizeof( AES_CTR_STATE ) );
    
    /* initialize the iv portion of the structure */
    memcpy( ctr_state->iv, iv, AES_BLOCK_SIZE );
}



int main(int argc, char* argv[]){
    
    /* descriptors used for various files */
    FILE *key_file;
    FILE *plaintext_file;
    FILE *ciphertext_file;
    
    /* length of hex data in bytes expected to be read in */
    unsigned long length;
    
    /* number of symbols to be read in */
    unsigned long num_symbols;
    
    /* running count of hex data converted to bytes and used by AES */
    unsigned long bytes_in;
    
    /* required by AES routines */
    AES_KEY aes_key;
    
    /* key data */
    unsigned char key     [AES_BLOCK_SIZE];
    
    /* initialization vector */
    unsigned char iv      [AES_BLOCK_SIZE];
    
    /* AES input and output blocks */
    unsigned char in_blk  [AES_BLOCK_SIZE];
    unsigned char out_blk [AES_BLOCK_SIZE];
    
    /* structure used to hold AES state */
    AES_CTR_STATE ctr_state;
    
    /* byte length of converted hex data */
    int in_blk_len;

    /* helper variables for returned status, iteration */
    int status;
    int i;
    
    /* timing flag, initialized to assume no display of timing statistics */
    int timing = TN;
    
    /* clock variables */
    clock_t start_t, end_t, total_t;
    double cpu_time;
    
    /* check command line arguments for validity */
    
    if ( argc < 3  || argc > 4 ) {
        /* must have at least key and plaintext files as parameters, with optional timing parameter */
        usage();
        exit (1);
    }
    else if ( argc == 4 ) {
        /* 3rd parameter specified, check to make sure it is timing parameter */
        if ( strcmp ( argv[3], "-t" )  == 0 ){
            /* print timing statistics */
            timing = TY;
        }
        else {
            /* bad timing parameter */
            usage();
            exit(1);
        }
    }
    

    /* open required files. if they dont exist, quit with error */
    
    key_file = fopen( argv[1], "rb" );
    if ( key_file == NULL ) {
        fprintf( stderr, "Bad Key File Name or File Doesn't Exist\n" );
        exit(1);
    }
    
    plaintext_file = fopen( argv[2], "rb" );
    if ( plaintext_file == NULL ) {
        fprintf( stderr, "Bad Plaintext File Name or File Doesn't Exist\n" );
        exit(1);
    }
    
    /* assign ciphertext file output to stdout */
    
    ciphertext_file = stdout;
    
    /* Set up iv  - the random part first */
    if ( !RAND_bytes( iv, AES_BLOCK_SIZE) / 2 ) {
        fprintf( stderr, "Could not initialize iv\n" );
        exit(1);
    }
    
    /* Now initialize the counter part of the iv  to 0 */
    memset( iv + AES_BLOCK_SIZE / 2, 0, AES_BLOCK_SIZE / 2 );
    
    /* Initialize the counter state structure used by openssl */
    init_ctr( &ctr_state, iv );
    
    /* Read key */
    
    status = getAESinput ( key_file,  key, &in_blk_len );
    
    /* quit on size error */
    if ( status || (in_blk_len != AES_BLOCK_SIZE ) ) {
        fprintf( stderr, "Bad Key Hex Data\n" );
        exit(1);
    }
    
    fclose( key_file );
    
    /* read plaintext file symbol length. if it is odd or exceeds allowed value, quit */
    
    fscanf( plaintext_file, "%lu\n", &num_symbols );

    /* make sure symbol count is within limit and even */
    
    if ( num_symbols > MAX_ENCRYPT_SYMBOLS || num_symbols == 0 ) {
        fprintf( stderr, "Bad Symbol Count In Plaintext File; Allowed: %lu  Specified: %lu\n", MAX_ENCRYPT_SYMBOLS, num_symbols );
    }
    else if ( num_symbols % 2 ) {
        fprintf( stderr, "Bad Plaintext File - Symbol Count Is Odd\n");
        exit(1);
    }
    else {
        /* set total byte count expected from hex data */
        length = num_symbols / 2;
    }
    
    
    /* Initialize encryption key */
    
    if ( AES_set_encrypt_key( key, 128, &aes_key ) ) {
        fprintf( stderr, "AES Initialization Failed\n" );
        exit(1);
    }
    
    
    /* Write out adjusted length to include iv information to be written as first ciphertext block */
    
    fprintf( ciphertext_file, "%lu\n", num_symbols + AES_BLOCK_SIZE * 2);
    
    /* Write out IV */
    i = 0;
    while ( i < AES_BLOCK_SIZE ) {
        fprintf( ciphertext_file, "%02x", iv[i++] );
    }

    /* initialize count of AES data bytes converted from hex data input */
    bytes_in = 0;
    
    /* initialize status variable used for while loop control */
    int loop_cnd = 1;
    
    /* initialize total time for possible use */
    total_t = (clock_t) 0;
    
    
    while ( loop_cnd ) {
        /* Read hex from paintext file & create AES128 block */
        if ( getAESinput ( plaintext_file,  in_blk, &in_blk_len ) ) {
            fprintf (stderr, "Final Data Frame Length Not Even, Bad Input Data\n");
            fprintf (stderr, "Check Plaintext Input For Odd Number Of Symbols\n");
            exit(1);
            break;
        }

        if ( in_blk_len == 0 ) {
            /* quit loop if no data was read */
            break;
        }
        else if ( in_blk_len < AES_BLOCK_SIZE ) {
            /*  
                final block is less than max block size.  No padding is necsssary in this AES mode
                of operation.  set loop exit condition, as there will be no more data to process
             */
            loop_cnd = 0;
        }
        
        /* increment total byte count read in by number just read */
        bytes_in = bytes_in + in_blk_len;
            
        /* start timing decryption here */
        start_t = clock();
        
        AES_ctr128_encrypt( in_blk, out_blk, in_blk_len, &aes_key, ctr_state.iv, ctr_state.ecount, & ctr_state.num );
            
        /* end timing here and accumulate */
        end_t = clock();
        total_t = total_t + (end_t - start_t);
        
        /* Write out ciphertext block */
            
        i = 0;
        while ( i < in_blk_len ) {
            fprintf( ciphertext_file, "%02x", out_blk[i++]);
        }
        
    }

    /* check to make sure that total bytes read in was expected quantity */
    
    if( bytes_in != length ) {
        fprintf( stderr, "Plaintext Data File Size Error.  Bytes Expected: %lu Bytes Found: %lu\n", length, bytes_in );
        exit(1);
    }
    
    /* Print out timing values if TA or TL specified */
    if ( timing == TY ) {
        cpu_time = ((double) total_t) / CLOCKS_PER_SEC;
        fprintf( stderr, "Total encryption time: %f\n", cpu_time );
    }

    
    fclose( plaintext_file );
    fclose( ciphertext_file );
    
    
    return 0;
}