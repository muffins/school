//
//  gencertparams.c
//
//
//  Created by Dennis Mirante on 5/2/14.
//
//

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>


struct issuer{
    long serial_number;
    long start_time;
    long end_time;
    char country[10];
    char organization[70];
    char common_name[70];
};


void usage ( void ) {
    fprintf ( stderr, "\n\nUsage: ./gencertparams validityparameters.txt\n");
    fprintf ( stderr, "where:\n" );
    fprintf ( stderr, "       validityparameters.txt - file to which binary information about the public key owner will be written\n");
    fprintf ( stderr, "\n" );
    fprintf ( stderr, "\n" );
}



// builds the file containing parameters to use for certificate generation
int main( int argc, char * argv[] ) {
    
    FILE    * out_file;
    
    struct  issuer id;
    char    * buffer;
    int     buffsize = 100;
    int     bytes_read;
    
    long    int_in;
    int     result;
    int     loop;
    
    
    buffer = (char *) malloc( buffsize + 1 );
    
    
    /* check command line arguments for validity */
    
    if ( argc != 2 ) {
        /* must have binary output file specified */
        usage();
        exit (1);
    }
    
    /* open required output file. if name bad, quit with error */
    
    out_file = fopen( argv[1], "wb" );
    if ( out_file == NULL ) {
        fprintf( stderr, "Bad Binary Output File Specification\n" );
        exit(1);
    }
    
    
    loop = 1;
    while ( loop ) {
        
        printf("\n");
        
        /* get certificate serial number.  limit it to between 1 and 1000 */
        
        while(1){
            printf("Enter Certificate Serial Number (Between 1 and 1000): ");
            bytes_read = getline( &buffer, (size_t *) &buffsize, stdin );
            if ( bytes_read > 1 ) {
                result = sscanf( buffer, "%4ld", &int_in );
                if( result == 1 ) {
                    if ( int_in > 0 && int_in < 1001 ) {
                        id.serial_number = int_in;
                        break;
                    }
                }
            }
        }
        
        printf( "\nYou Will Now Be Asked To Enter The Certificate Not Before Time And Not After Times.\n\n" );
        printf( "The Not Before Time Is The Number Of Seconds After Creation When The Certificate Will\n" );
        printf( "Become Valid.  If You Want It To Be Valid Immediately, Enter 0.\n\n" );
        printf( "The Not After Time Is The Number Of Seconds After Creation When The Cerificate Will\n" );
        printf( "Expire And Become Invalid.  You Must Enter A Significant Number of Seconds To Prevent\n" );
        printf( "The Certificate From Expiring Before Testing Is Complete.  For Example, To Have The\n" );
        printf( "Certificate Expire One Day After Creation, The Number Entered Would Be 60*60*24 = 86400\n\n");
        
        /* get certificate start time in seconds from creation time */
        
        while(1){
            printf("Enter Certificate Not Before Time In Seconds ( 0 For Creation Time ): ");
            bytes_read = getline( &buffer, (size_t *) &buffsize, stdin );
            if ( bytes_read > 1 ) {
                result = sscanf( buffer, "%ld", &int_in );
                if( result == 1 ) {
                    if( int_in >= 0 ) {
                        id.start_time = int_in;
                        break;
                    }
                }
            }
        }
        
        
        /* get certificate not after time in seconds from creation time */
        
        while(1){
            printf("Enter Certificate Not After Time In Seconds : ");
            bytes_read = getline( &buffer, (size_t *) &buffsize, stdin );
            if ( bytes_read > 1 ) {
                result = sscanf( buffer, "%ld", &int_in );
                if( result == 1 ) {
                    if( int_in >= 0 ) {
                        id.end_time = int_in;
                        break;
                    }
                }
            }
        }
        
        
        /* get 2 character country identifier and capitalize it */
        while ( 1 ) {
            printf("Enter 2 Character Alphabetic Country Code (ie., US): ");
            bytes_read = getline( &buffer, (size_t *) &buffsize, stdin );
            
            if ( bytes_read == 3 ) {
                if ( isalpha( buffer[0] ) && isalpha( buffer[1] ) ) {
                    buffer[0] = toupper( buffer[0] );
                    buffer[1] = toupper( buffer[1] );
                    buffer[2] = '\0';
                    strcpy( id.country, buffer );
                    break;
                }
            }
        }
        
        
        /* Get organization name - Specify Minimum of 10 characters */
        
        while ( 1 ) {
            printf("Enter 10 Character Minimum To 64 Character Maximum Organization Name (ie., Crypto Class): ");
            bytes_read = getline( &buffer, (size_t *) &buffsize, stdin );
            
            if ( bytes_read >= 11 && bytes_read <= 65 ) {
                buffer[ bytes_read - 1 ] = '\0';
                strcpy( id.organization, buffer );
                break;
            }
        }
        
        
        /* Get key owner's name - Specify Minimum of 10 characters */
        
        while ( 1 ) {
            printf("Enter 10 Character Minimum To 64 Character Maximum Key Owner Name (ie., Bob The Slob): ");
            bytes_read = getline( &buffer, (size_t *) &buffsize, stdin );
            
            if ( bytes_read >= 11 && bytes_read <= 65 ) {
                buffer[ bytes_read - 1 ] = '\0';
                strcpy( id.common_name, buffer );
                break;
            }
        }
        
        printf( "\nYou Have Specified:\n\n" );
        
        printf( "Certificate Serial Number = %ld\n", id.serial_number );
        printf( "Not Before Time           = %ld\n", id.start_time );
        printf( "Not After Time            = %ld\n", id.end_time );
        printf( "Country Code              = %s\n" , id.country );
        printf( "Organization Name         = %s\n" , id.organization );
        printf( "Key Owner Name            = %s\n",  id.common_name );
        
        while ( 1 ) {
            printf( "\nType a To Accept, Type r To Reenter (a or r) ?:" );
            bytes_read = getline( &buffer, (size_t *) &buffsize, stdin );
            
            if ( bytes_read == 2 ) {
                if ( buffer[0] == 'a' || buffer[0] == 'A' ) {
                    /* clear loop control variable and go write */
                    loop = 0;
                    break;
                }
                else if( buffer[0] == 'r' || buffer[0] == 'R' ){
                    /* go back to top and reenter everything */
                    break;
                }
            }
        }
        
    }
    
    /* Write the file */
    fwrite( &id, sizeof( struct issuer ), 1, out_file );
    fclose ( out_file );
    
    printf( "\n%s Written With Key Owner Information\n\n", argv[1] );
}