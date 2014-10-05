//
//  ctrhdr.h
//  
//
//  Created by Dennis Mirante on 3/27/14.
//
//

#ifndef _ctrhdr_h
#define _ctrhdr_h

#include <openssl/aes.h>


/* Timing values, no or yes */
enum timings {TN, TY};

/*
 * Maximum Symbol Counts.  These values arbitrarily set.
 * MAX_ENCRYPT_SYMBOLS is 2 * AES_BLOCK_SIZE less than MAX_DECRYPT_SYMBOLS to
 * account for increase in size of ciphertext file due to iv being written
 * as first data block.  MAX_DECRYPT_SYMBOLS is 2**32-2, to assure even value.
 */
#define MAX_DECRYPT_SYMBOLS ((unsigned long) 8589934590)
#define MAX_ENCRYPT_SYMBOLS ((unsigned long) MAX_DECRYPT_SYMBOLS - AES_BLOCK_SIZE * 2)

/* structure used to hold AES state between AES function invocations */
typedef struct
{
    unsigned int  num;
    unsigned char ecount[AES_BLOCK_SIZE];
    unsigned char iv  [AES_BLOCK_SIZE];
}AES_CTR_STATE;



#endif
