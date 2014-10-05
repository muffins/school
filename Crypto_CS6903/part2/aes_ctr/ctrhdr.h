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

/* HMAC key is 32 bytes */
//#define HMAC_KEY_SIZE 32

/* HMAC tag size is 32 bytes ( sha2 ) */
//#define HMAC_TAG_SIZE 32

/* maximum key size is 64 bytes for sha256 */
#define MAX_KEY_SIZE        64

/* use these later if any key size can be accepted */
#define KEY_MAX_DIGITS      4
#define KEY_MAX_LENGTH      1024
#define KEY_MIN_LENGTH      1

/*
 * maximum hex input length - 2 * expected byte count.  This should cover the maximum number of hex symbols to
 * be counted and converted at any one time.  This should be sized to hold the biggest key as represented as
 * hex symbols and and any other hex symbol input.
 */
#define MAX_HEX_INP_SYM    KEY_MAX_LENGTH * 2

/*  HMAC prefix storage type and output format used in file header generation */
/****** WARNING - If PREFIX_FORMAT changes, adjust HMAC_HDR_SIZE  ******/

#define PREFIX_TYPE         unsigned int
#define PREFIX_FORMAT       "%08x"
#define PREFIX_FLD_SZ       4           /* in bytes */


/*  HMAC type storage type and output format used in file header generation */
/****** WARNING - If HMAC_TYPE_FORMAT changes, adjust HMAC_HDR_SIZE  ******/

#define HMAC_TYPE_TYPE      unsigned int
#define HMAC_TYPE_FORMAT    "%08x"
#define HMAC_TYPE_FLD_SZ    4           /* in bytes */


/*  HMAC timestamp storage type and output format used in file header generation */
/****** WARNING - If TIMESTAMP_FORMAT changes, adjust HMAC_HDR_SIZE  ******/

#define TIMESTAMP_TYPE      unsigned int
#define TIMESTAMP_FORMAT    "%08x"
#define TIMESTAMP_FLD_SZ    4           /* in bytes */


/*  HMAC length storage type and output format used in file header generation */
/****** WARNING - If HMAC_LENGTH_FORMAT changes, adjust HMAC_HDR_SIZE  ******/

#define HMAC_LENGTH_TYPE    unsigned int
#define HMAC_LENGTH_FORMAT  "%08x"
#define HMAC_LENGTH_FLD_SZ  4           /* in bytes */

/* Maximum Tag Size in bytes  - accomodates MD5 thru SHA3-512 */
/****** WARNING - If HMAC_TAG_SIZE changes, adjust HMAC_HDR_SIZE  ******/

#define MAX_HMAC_TAG_SIZE   64
#define HMAC_TAG_FLD_SZ     MAX_HMAC_TAG_SIZE   /* Tag size in bytes */

/*  HMAC prefix storage type and output format used in file header generation */
/****** WARNING - If SUFFIX_FORMAT changes, adjust HMAC_HDR_SIZE  ******/

#define SUFFIX_TYPE         unsigned int
#define SUFFIX_FORMAT       "%08x"
#define SUFFIX_FLD_SZ       4           /* in bytes */

#define PREFIX_VALUE        819234589
#define SUFFIX_VALUE        985432918

/*
 * ***** WARNING - IF PREFIX_FORMAT or HMAC_LENGTH_FORMAT or TIMESTAMP_FORMAT or HMAC_LENGTH_FORMAT or MAX_HMAC_TAG_SIZE OR SUFFIX_FORMAT changes, adjust HMAC_HDR_SIZE  ******
 *
 * HMAC header size is set depending on HMAC_LENGTH_FORMAT (8 bytes), MAX_HMAC_TAG_SIZE (64), and TIMESTAMP_FORMAT (8 bytes)
 *
 */
#define HMAC_HDR_SIZE       (PREFIX_FLD_SZ + HMAC_TYPE_FLD_SZ + HMAC_LENGTH_FLD_SZ + HMAC_TAG_FLD_SZ + TIMESTAMP_FLD_SZ + SUFFIX_FLD_SZ)

/* Define file character positons in header for quick positioning */
#define F_PREFIX_POS            0
#define F_HMAC_TYPE_POS         ( F_PREFIX_POS + PREFIX_FLD_SZ * 2 )
#define F_HMAC_LEN_POS          ( F_HMAC_TYPE_POS + HMAC_TYPE_FLD_SZ * 2 )
#define F_HMAC_TAG_POS          ( F_HMAC_LEN_POS + HMAC_LENGTH_FLD_SZ * 2)
#define F_TIMESTAMP_POS         ( F_HMAC_TAG_POS + HMAC_TAG_FLD_SZ * 2)
#define F_SUFFIX_POS            ( F_TIMESTAMP_POS + TIMESTAMP_FLD_SZ * 2 )
#define F_DATA_START_POS        ( F_SUFFIX_POS + SUFFIX_FLD_SZ * 2 + 1 ) /* takes into account \n */

/* Max timestamp difference in seconds for validity */
#define MAX_TIMESTAMP_DIFF   120


/* structure used to hold timestamp in hex and binary */
typedef struct
{
    unsigned int  timestamp_bin;
    unsigned char timestamp_hex[ TIMESTAMP_FLD_SZ * 2 ];
}TIMESTAMP_STRUCT;


/* types for encoding used by keygen and sign */
enum encode_types { MD5, SHA1, SHA224, SHA256, SHA384, SHA512, AES128, NUM_HMAC_TYPES = AES128, NUM_ENCODE_TYPES, NUM_KEY_TYPES = NUM_ENCODE_TYPES };


/* look up encoding via either numeric or string */
enum encode_lookup_types { LIT, NUM, NUM_ENCODE_LOOKUP_TYPES };

/* encode lookup argument, can either be integer or string, as specified type */

struct encode_arg
{
    enum encode_lookup_types type;
    union {
        char str[10];
        int  num_id;
    }arg;
};


/* encoding attributes for keygen or sign use */

struct encode_attr
{
    enum encode_types type;
    char name[10];
    int default_keysize;
    int output_size;
    const EVP_MD *md;
};

int get_encode_attr( FILE * error_file, int prnt_error, struct encode_arg * arg, struct encode_attr * attr_ptr );

#endif
