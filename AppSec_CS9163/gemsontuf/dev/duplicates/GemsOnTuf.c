/*
 * #Usage: 
 * require 'GemsOnTuf'
 * #this is equivalent to tuf.interposition.configure()
 * #I also don't think we need the second and third arguments
 * #unless we're using SSLs
 * tuf = GemsOnTuf::TUF.new( 'tuf.interposition.json', '', '' )   
 * tuf.method()
 * #Methods:
 * tuf.urlOpen( 'urlString' )
 * tuf.urlOpenTwo( 'urlString' )
 * tuf.urlRetrieve( 'urlString', 'filename' )
 * #etc
 * #The above run if put into a ruby file.
 * 
 */

#include "ruby.h"
#include "tuf_interface.h"

//this holds the objects 
VALUE GemsOnTuf = Qnil;
VALUE TUF = Qnil;

void Init_GemsOnTuf();

//declare methods
VALUE method_TUFConfigure( VALUE self, VALUE par0, VALUE par1, VALUE par2 );
VALUE method_TUFurlOpen( VALUE self, VALUE rbUrl );
VALUE method_TUFDeconfigure( VALUE self );

//place holders for now
VALUE method_TUFurlOpenTwo( VALUE self, VALUE rbUrl );
VALUE method_TUFurlRetrieve( VALUE self, VALUE rbURL, VALUE rbFile );

//init methods ~ require 'GemsOnTuf'
void Init_GemsOnTuf() {
	GemsOnTuf = rb_define_module("GemsOnTuf");
    TUF = rb_define_class_under( GemsOnTuf, "TUF", rb_cObject );
	rb_define_method( TUF, "initialize", method_TUFConfigure, 3 );
	rb_define_method( TUF, "deconfigure", method_TUFDeconfigure, 0 );
	rb_define_method( TUF, "urlOpen", method_TUFurlOpen, 1 );
	rb_define_method( TUF, "urlOpenTwo", method_TUFurlOpenTwo, 1 );
	rb_define_method( TUF, "urlRetrieve", method_TUFurlRetrieve, 2 );
}


//bool Py_TUF_configure(char* tuf_intrp_json, char* p_repo_dir, char* p_ssl_cert_dir)
//returns a bool, I think the exception from Python closes the program anyway though
//so this might not be necessary. 
VALUE method_TUFConfigure( VALUE self, VALUE par0, VALUE par1, VALUE par2 ) {
	char* argOne = StringValuePtr( par0 );
	char* argTwo = StringValuePtr( par1 );
	char* argThr = StringValuePtr( par2 );
	
	bool worked = Py_TUF_configure( argOne, argTwo, argThr );
	if ( worked )
		return self; 
	return Qnil;
}


//char* Py_TUF_urllib_urlopen( char* url ) 
VALUE method_TUFurlOpen( VALUE self, VALUE rbUrl ) {
	char* url = StringValuePtr( rbUrl );
	
	char* readUrl = Py_TUF_urllib_urlopen( url );
	
	if ( readUrl == NULL )
		return rb_str_new2( "err" );
	return rb_str_new2( readUrl );
}

//bool Py_TUF_urllib2_urlopen(char* url)
VALUE method_TUFurlOpenTwo( VALUE self, VALUE rbUrl ) {
	char* url = StringValuePtr( rbUrl );
	
	bool worked = Py_TUF_urllib2_urlopen( url );
	
	if ( worked ) 
		return Qtrue;
	return Qfalse;
}


//bool Py_TUF_urllib_urlretrieve(char* url, char* fname);
VALUE method_TUFurlRetrieve( VALUE self, VALUE rbUrl, VALUE rbFile ) {
	char* url = StringValuePtr( rbUrl );
	char* file = StringValuePtr( rbFile );
	
	bool worked = Py_TUF_urllib_urlretrieve( url, file );
				  
	if ( worked )
		return Qtrue;
	return Qfalse;
}

//void Py_TUFDeconfigure();

VALUE method_TUFDeconfigure( VALUE self ) {
	printf( "I don't know do anything right now.\n" );
	return Qtrue;
}


