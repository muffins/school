//
//  keyverify.c
//
//
//  Created by Dennis Mirante on 5/1/14.
//
//


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>


struct issuer{
    long serial_number;
    long start_time;
    long end_time;
    char country[10];
    char organization[70];
    char common_name[70];
};


void usage ( void ) {
    fprintf ( stderr, "\n\nUsage: ./keyverify signpublickey.txt certificate.txt crs.txt\n");
    fprintf ( stderr, "where:\n" );
    fprintf ( stderr, "       signpublickey.txt is a file in pem format containing the CA's RSA public key\n" );
    fprintf ( stderr, "       certificate.txt is a file in pem format containing the X509 certificate\n" );
    fprintf ( stderr, "       crs.txt is a binary file containing information about the public key owner\n");
    fprintf ( stderr, "\n" );
    fprintf ( stderr, "Output is YES or NO depending on certificate validity\n");
    fprintf ( stderr, "\n" );
    fprintf ( stderr, "Program output may be redirected from stdout using the > symbol\n" );
    fprintf ( stderr, "\n" );
}



// verify personalization fields contained in certificate against those expected of issuer
// returns 1 if all fields agree, zero otherwise

int verifyCert ( X509 * cert, struct issuer id ) {

    /* Variables to hold fields extracted from certificate */

    X509_NAME *subject_name;    /* ptr to subject name structure */
    X509_NAME_ENTRY *entry;     /* ptr to entry within subject name */
    ASN1_STRING *data;          /* ptr tostring data extracted from entry in ASN1_STRING format */
    unsigned char *utf8;        /* ptr to charater string in unicode format */
    int idx;                    /* index to entry within subject name structure */
    
    /* Helper variables */
    int result;
    
    /* Extract subject name containing personalization params from the certificate */
    if( ! ( subject_name = X509_get_subject_name( cert ))) {
        fprintf( stderr, "X509_get_subject_name() Failed\n" );
        exit(1);
    }
    
    /*
     * All string comparisons will first specify an index to the desired field,
     * then extract the entry using the index, then extract the data that is in
     * ASN1_STRING format, then convert the extracted data to utf8 format for
     * comparison.  The utf8 memory must be returned to openssl after use.
     */
    
    /* get and compare common name (the guy's name ) */
    idx = X509_NAME_get_index_by_NID( subject_name, NID_commonName, -1 );
    entry = X509_NAME_get_entry( subject_name, idx );
    data = X509_NAME_ENTRY_get_data ( entry );
    ASN1_STRING_to_UTF8( &utf8, data );

    printf( "Common Name = %s\n", utf8 );
    result = strcmp( (const char *)utf8, id.common_name );
    OPENSSL_free( utf8 );
                    
    if ( result != 0 ) return 0;
    
    /* get and compare country name */
    idx = X509_NAME_get_index_by_NID( subject_name, NID_countryName, -1 );
    entry = X509_NAME_get_entry( subject_name, idx );
    data = X509_NAME_ENTRY_get_data ( entry );
    ASN1_STRING_to_UTF8( &utf8, data );
    
    printf( "Country = %s\n", utf8 );
    result = strcmp( (const char *)utf8, id.country );
    OPENSSL_free( utf8 );
                    
    if ( result != 0 ) return 0;


    /* get and compare organization name */
    idx = X509_NAME_get_index_by_NID( subject_name, NID_organizationName, -1 );
    entry = X509_NAME_get_entry( subject_name, idx );
    data = X509_NAME_ENTRY_get_data ( entry );
    ASN1_STRING_to_UTF8( &utf8, data );
    
    printf( "Organization = %s\n", utf8 );
    result = strcmp( (const char *)utf8, id.organization );
    OPENSSL_free( utf8 );
    
    if ( result != 0 ) return 0;

    
    /* Get the serial number certificate.  We will expect it to match */
    ASN1_INTEGER *serial = X509_get_serialNumber(cert);
    long serial_number = ASN1_INTEGER_get (serial);
    printf( "Serial Number = %ld\n", serial_number );
    
    if ( serial_number != id.serial_number ) return 0;
    
    /* All fields matched, return with success */
    return 1;
}


extern int errno;

//verify certificate using expected issuer parameters
int main( int argc, char ** argv) {

    /* descriptors used for various files */
    FILE *issuer_params;
    FILE *certificate;
    FILE *public;

    /* Structure common to generator and user of certificate used in validating it */
    struct issuer id;

    /*
     * Structures to hold public key and key specified in certificate
     * Free allocated memory after use
     */
    EVP_PKEY *pub_key;
    EVP_PKEY *cert_pub_key;
    EVP_PKEY *crs_pub_key;
    
    RSA * rsa_pub;
    RSA * crs_pub;

    /* Pointer to certificate */
    X509    *cert;
    
    /* helper variables */
    int result;
    int bytes;
    
    OpenSSL_add_all_algorithms();
    

    /* check command line arguments for validity */
    
    if ( argc != 4 ) {
        /* must have public key, certificate, and keyfile owner information files */
        usage();
        exit (1);
    }
    
    /* open required files. if they dont exist, quit with error */
    
    public = fopen( argv[1], "rb" );
    if ( public == NULL ) {
        fprintf( stderr, "Bad RSA Public Key File Name or File Doesn't Exist\n" );
        exit(1);
    }
    
    certificate = fopen( argv[2], "rb" );
    if ( certificate == NULL ) {
        fprintf( stderr, "Bad X509 Certificate File Name or File Doesn't Exist\n" );
        exit(1);
    }
    
    issuer_params = fopen( argv[3], "rb" );
    if ( !issuer_params ){
        fprintf( stderr, "Bad Public Key Owner Information File Name or File Doesn't Exist\n");
        exit(1);
    }
    
    
    /* Read the CA public key and close the file */
//    pub_key = PEM_read_PUBKEY( public, NULL, NULL, NULL );
    rsa_pub = PEM_read_RSAPublicKey( public, NULL, NULL, NULL );
    if ( rsa_pub == NULL ){
        fprintf( stderr, "Bad RSA Public Key File\n");
        exit(1);
    }
    
    fclose ( public );
    
    /* allocate a key structure */
    pub_key = EVP_PKEY_new();
    if( pub_key == NULL ) {
        fprintf( stderr, "pub_key = EVP_PKEY_new() failed\n" );
        exit(1);
    }

    /* assign the rsa key to the key structure */
    if ( EVP_PKEY_assign_RSA( pub_key, rsa_pub ) == 0 ) {
        fprintf( stderr, "EVP_PKEY_assign_RSA( pub_key, rsa_pub ) failed\n" );
        exit(1);
    }


    /* Read the X509 certificate and close the file */
    cert = PEM_read_X509( certificate, NULL, NULL, NULL);
    if ( cert == NULL ){
        fprintf( stderr, "Bad X509 Certificate File\n");
        exit(1);
    }
    
    fclose( certificate );

    
    /* Read the CA public key and close the file */
    //    pub_key = PEM_read_PUBKEY( public, NULL, NULL, NULL );
    crs_pub = PEM_read_RSAPublicKey( issuer_params, NULL, NULL, NULL );
    if ( crs_pub == NULL ){
        fprintf( stderr, "Bad Public Public Key Owner Information File\n");
        exit(1);
    }
    
    /* allocate a key structure */
    crs_pub_key = EVP_PKEY_new();
    if( crs_pub_key == NULL ) {
        fprintf( stderr, "crs_pub_key = EVP_PKEY_new() failed\n" );
        exit(1);
    }
    
    /* assign the rsa key to the key structure */
    if ( EVP_PKEY_assign_RSA( crs_pub_key, crs_pub ) == 0 ) {
        fprintf( stderr, "EVP_PKEY_assign_RSA( pub_key, rsa_pub ) failed\n" );
        exit(1);
    }

    
    /* Initialize issuer struct with binary information from key owner information file and close the file */
    bytes = fread( &id, sizeof(struct issuer ), 1, issuer_params );
    if ( bytes == 0 ) {
        fprintf( stderr, "Bad Public Key Owner Information File\n");
        exit(1);
    }
    
    fclose ( issuer_params );
    
    
    /* read the public key contained in the certificate */
    if ( ( cert_pub_key = X509_get_pubkey( cert ) ) == NULL ) {
        fprintf(stderr, "Cannot Read Public Key From x509 Certificate\n");
        exit(1);
    }
    
    /* check the certificate signature using CA key */
    result = X509_verify( cert, pub_key );
    
    if ( result != 1 ) {
        fprintf( stderr, "Certificate Signature No Good\n" );
        fprintf( stderr, "result = %d\n", result );
        fprintf( stderr, "Value of errno: %d\n", errno );
        perror( "Error printed by perror" );
        fprintf( stdout, "NO\n" );
        fflush( stdout );
        exit(1);
    }
    
    /* compare public in the crs with public key in certificate */
    result = EVP_PKEY_cmp ( cert_pub_key, crs_pub_key );
    
    /* free allocated memory structures */
    EVP_PKEY_free( crs_pub_key );
    EVP_PKEY_free( cert_pub_key );
    EVP_PKEY_free( pub_key );
    
    
    if ( result != 1  ) {
        fprintf( stderr, "No Match On Public Key in CSR And Public Key Contained In Certificate\n");
        fprintf( stdout, "NO\n");
        fflush ( stdout );
        exit(1);
    }
    
    /* Do rest of X509 certificate verification including check to make sure it has not expired */
    /* Certificate chain will only have one certificate in it */
    X509_STORE_CTX  *ctx;
    X509_STORE      *store;
    
    /* create certificate store */
    if( ! ( store = X509_STORE_new() ) ){
        fprintf( stderr, "X509_STORE_new() Failed\n" );
        exit(1);
    }
    
    /* load certificate into store */
    X509_STORE_add_cert( store, cert );
    
    /* create context structure for validation */
    if( ! ( ctx = X509_STORE_CTX_new() ) ){
        fprintf( stderr, "X509_STORE_CTX_new() Failed\n" );
        exit(1);
    }
    
    /* Initialize ctx structure for verification */
    X509_STORE_CTX_init( ctx, store, cert, NULL);
    
    /* verify it */
    result = X509_verify_cert( ctx );
    
    /* free allocated memory for store structure */
    X509_STORE_free( store );
    
    if( result != 1 ){
        fprintf( stderr, "Certificate failed verification, code = %d\n", result );
        fprintf( stderr, "%s\n", X509_verify_cert_error_string(ctx->error) );
        fprintf( stdout, "NO\n" );
        fflush( stdout );
        exit(1);
    }

    /* free allocated memory for ctx structure */
    X509_STORE_CTX_free( ctx );
    
    /* Verify personalization parameters against those in certificate */
    result = verifyCert ( cert, id );
    
    /* done with certificate, free memory allocated for it */
    X509_free( cert );

    /* write result to stdout */
    if ( result == 1 ) {
        fprintf( stdout, "YES\n" );
    }
    else {
        fprintf( stdout, "NO\n" );
        fprintf( stderr, "verifyCert Failed\n");
    }
    
    return(0);
    
}