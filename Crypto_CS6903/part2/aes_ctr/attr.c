//
//  attr.c
//  
//
//  Created by Dennis Mirante on 4/19/14.
//
//

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <openssl/hmac.h>
#include "ctrhdr.h"


/*
 * this routine is called to obtain the attributes for a particular encoding type
 * the arguement is in a union that can either be a character string or a number
 * if a string, the string is compared to known encodings and if one is found, its
 * attributes are returned.  if a number, then the attribute is looked up and returned
 * if no attribute can be found, 1 is returned, 0 otherwise
 * if prnt_error is non-zero, diagnostics will be printed to error_file
 */
 
int get_encode_attr( FILE * error_file, int prnt_error, struct encode_arg * arg, struct encode_attr * attr_ptr ) {
    
    static struct encode_attr attrib[ NUM_ENCODE_TYPES ] = {
        { MD5,      "md5",    16, 16, NULL },
        { SHA1,     "sha1",   20, 20, NULL },
        { SHA224,   "sha224", 28, 28, NULL },
        { SHA256,   "sha256", 32, 32, NULL },
        { SHA384,   "sha384", 48, 48, NULL },
        { SHA512,   "sha512", 64, 64, NULL },
        { AES128,   "aes128", 16, 16, NULL }
    };
    
    int i;
    
    /* this is a pain in the ass.  these can not be specified at compile time, must be set at run time */

    attrib[MD5].md      = EVP_md5();
    attrib[SHA1].md     = EVP_sha1();
    attrib[SHA224].md   = EVP_sha224();
    attrib[SHA256].md   = EVP_sha256();
    attrib[SHA384].md   = EVP_sha384();
    attrib[SHA512].md   = EVP_sha512();
    

    if ( arg->type == LIT ) {

        /* get all alpha characters to lower case */

        for ( i = 0; i < strlen( arg->arg.str ); i++ ) {
            if ( isalpha( arg->arg.str[i] ) ) arg->arg.str[i] = tolower( arg->arg.str[i] );
        }
    
        /* compare argument string to defined types, when one is found, copy the attributes to return arg */

        for ( i = 0; i < NUM_ENCODE_TYPES; i++ ) {
            
            if (strcmp( arg->arg.str, attrib [i].name ) == 0 ) {
            
                /* copy attributes into structure for return */
                strcpy( attr_ptr->name, attrib[i].name );
                attr_ptr->type = attrib[i].type;
                attr_ptr->default_keysize = attrib[i].default_keysize;
                attr_ptr->output_size = attrib[i].output_size;
                attr_ptr->md = attrib[i].md;
                return 0;
            }
        }
        
        if( prnt_error ) {
            /* couldn't find matching encoding */
            fprintf( error_file, "get_encode_attr - UNKNOWN Encoding Type %s\n", arg->arg.str );
            return 1;
        }
    }

    else  if (arg->type == NUM ) {

        /* check encoding within range */
        
        if ( arg->arg.num_id < 0 || arg->arg.num_id > NUM_ENCODE_TYPES ) {
            
            if( prnt_error ) fprintf( error_file, "get_encode_attr - UNKNOWN Encoding Number %d\n", arg->arg.num_id );
            return 1;
        }
        else {
            /* lookup the type via its id and return it */
            i = arg->arg.num_id;
            /* copy attributes into structure for return */
            strcpy( attr_ptr->name, attrib[i].name );
            attr_ptr->type = attrib[i].type;
            attr_ptr->default_keysize = attrib[i].default_keysize;
            attr_ptr->output_size = attrib[i].output_size;
            attr_ptr->md = attrib[i].md;
            return 0;
        }
    }
    
    if( prnt_error ) fprintf( error_file, "get_encode_attr - Bad Argument Type %d\n", arg->type );
    return 1;
}