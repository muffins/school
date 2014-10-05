/*
* Application Security Fall 2013
* Team Red - Project 3
*
* Nick Anderson
* Pan Chan
* Anthony
* Nektarios
*
* This C code acts as the interface to call TUF functionality
* from other languages. This module should sit between Python, and
* whichever destination language one desires.
*
* Compiling:
* gcc tuf_interface.c -o tuf_interface -lpython2.7
*
* You must have python-dev installed for the linker to find the python2.7 libraries.
* Also note, that you *must* have the Python.h include before other standard header
* includes. This is per Python 3's documentation regarding how to do the python extensions
* with c.
*
* Additionally you should have TUF installed via python. This is required because
* we import the tuf module directly in the code here.
*
* Best tutorial I've found thus far: http://www.linuxjournal.com/article/8497?page=0,2
*/


//#include "python2.7/Python.h"

#include "tuf_interface.h"

/*
 * Pointer to keep track of the TUF Python Configure object.
 * This is needed for the Deconfigure method as it's paramter
 */
PyObject *configDict = NULL;
int _fileLength;

/*
* Method to call TUFs configure method. This function takes the JSON interposition filename
* as well as the parent repository directory and the parent ssl certificate directory, and
* configures TUF to interpose on update calls
*/
int Py_TUF_configure(char* tuf_intrp_json, char* p_repo_dir, char* p_ssl_cert_dir) {
    // Init the python env
    Py_Initialize();
    PyObject *moduleName;
    PyObject *tufInterMod;
    PyObject *path;
    PyObject *currentDirectory;
    //CAN BE REMOVED IF THIS WORKS
    //PyObject *configFunction;
    //PyObject *args;
    //PyObject *arg0;
    //PyObject *arg1;
    //PyObject *arg2;

	//add the current directory to the places to search for TUF
	//Do we even need this anymore? I don't think so.
	path = PySys_GetObject( "path" );
	currentDirectory = PyString_FromString( "." );
	PyList_Append( path, currentDirectory );
	Py_XDECREF( currentDirectory );

	/* import tuf module into the interpreter ~ import tuf.interposition */
	moduleName = PyString_FromString( "tuf.interposition" );
	tufInterMod = PyImport_Import( moduleName );
	if ( tufInterMod == NULL ) {
		PyErr_Print();
		return 0;
	}
	Py_XDECREF( moduleName );
	
	/* python equivalent ~ tuf.interposition.configure( tuf_intrp_json, p_repo_dir, p_ssl_cert_dir ) */
	configDict = PyObject_CallMethod( tufInterMod, (char*)"configure", "(sss)", 
									  tuf_intrp_json, p_repo_dir, p_ssl_cert_dir );
	if ( configDict == NULL ) {
		PyErr_Print();
		return 0;
	}
	Py_XDECREF( tufInterMod );
	
	//DELETE ALL THESE COMMENTS IF THIS WORKS
	
	//get the configure function from tuf.interposition
	/*
	configFunction = PyObject_GetAttrString( tufInterMod, "configure" );
	if ( configFunction == NULL ) {
		PyErr_Print();
		return false;
	}
	Py_XDECREF( tufInterMod );
	
	//convert arguements into Python types and create tuple for CallObject function
	args = PyTuple_New( 3 );
    arg0 = PyString_FromString( tuf_intrp_json );
    PyTuple_SetItem(args, 0, arg0);
    arg1 = PyString_FromString( p_repo_dir );
    PyTuple_SetItem(args, 1, arg1);
    arg2 = PyString_FromString( p_ssl_cert_dir );
    PyTuple_SetItem(args, 2, arg2);

	//calls the config function from the tuf.interposition module
	//returns a dictionary with the configurations	
	//we are currently storing this globally 	
	configDict = PyObject_CallObject( configFunction, args );

	Py_XDECREF( configFunction );
	Py_XDECREF( args );

	if ( configDict == NULL ) {
		PyErr_Print();
		return false;
	}
	*/
	printf( "TUF configured.\n" );
	return 1;
}


/*
* This method calls the TUF urlopen function, which opens a URL through TUF.
*/
char* Py_TUF_urllib_urlopen(char* url) {
    char* fname = "./.tmp_data_dump.raw";
    PyObject *urllibMod;
	PyObject *args;
	PyObject *http_resp;
	PyObject *data;

	/* Load the urllib_tuf module ~ from tuf.interposition import urllib_tuf */
	urllibMod = PyImport_AddModule( "urllib_tuf" );
	if ( urllibMod == NULL ) {
		PyErr_Print();
		return NULL;
	}
	
	/* call ~ http_resp = tuf.interposition.urlopen( url ) */
	http_resp = PyObject_CallMethod( urllibMod, (char *)"urlopen", "(s)", url );
	if ( http_resp == NULL ) {
		PyErr_Print();
		return NULL;
	}
	Py_XDECREF( urllibMod );
	
	/* call ~ data = http_resp.read() */
	data = PyObject_CallMethod( http_resp, (char *)"read" , NULL, NULL );
	if ( data == NULL ) {
		PyErr_Print();
		return NULL;
	}
	Py_XDECREF( http_resp );
	
    FILE *fp;
    fp = fopen(fname, "w");
    PyObject_Print(data, fp, Py_PRINT_RAW);
    fclose(fp);
    
    //this char *resp should be moved to the top
    /*
    char *resp;
    args = PyTuple_New( 1 );
	PyTuple_SetItem(args, 0, data);
    
	_fileLength = PyString_Size( http_resp );

	if ( !PyArg_ParseTuple( args, "s#", &resp, &_fileLength ) ) {
		PyErr_Print();
		return NULL;
	}
	Py_XDECREF( data );

    // Return the file
	return resp;
	*/
	
	//below can be deleted if the above works
	Py_XDECREF( data );
	
    // Return the name of the file
	return fname;
}

/*
* This method calls the TUF urlopen function from tuf.interposition.urllib2_tuf
*/
char* Py_TUF_urllib2_urlopen(char* url) {
    char* fname = "./.tmp_data_dump.raw";
    PyObject *urllibMod;
	PyObject *args;
	PyObject* http_resp;
	PyObject* data;

	/* Load the urllib_tuf module ~ from tuf.interposition import urllib_tuf */
	urllibMod = PyImport_AddModule( "urllib2_tuf" );
	if ( urllibMod == NULL ) {
		PyErr_Print();
		return NULL;
	}
	
	/* call ~ http_resp = tuf.interposition.urlopen( url ) */
	http_resp = PyObject_CallMethod( urllibMod, (char *)"urlopen", "(s)", url );
	if ( http_resp == NULL ) {
		PyErr_Print();
		return NULL;
	}
	Py_XDECREF( urllibMod );
	
	/* call ~ data = http_resp.read() */
	data = PyObject_CallMethod( http_resp, (char *)"read" , NULL, NULL );
	if ( data == NULL ) {
		PyErr_Print();
		return NULL;
	}
	Py_XDECREF( http_resp );
    

    /* Dump the data out to a file */
    FILE *fp;
    fp = fopen(fname, "w");
    PyObject_Print(data, fp, Py_PRINT_RAW);
    fclose(fp);
    
	/*
	//this char* resp should be moved to the top.
    char *resp;
    args = PyTuple_New( 1 );
	PyTuple_SetItem(args, 0, data);
    
	_fileLength = PyString_Size( data );
    
	if ( !PyArg_ParseTuple( args, "s#", &resp, &_fileLength ) ) {
		PyErr_Print();
		return NULL;
	}

    // Return the file
	return resp;
	*/
	Py_XDECREF( data );
	 
    // Return the name of the file
	return fname;
}


/*
* This method calls the TUF urlretreive function, which retrieves a URL through TUF.
* The value returned is the name of the locally retrieved file.
*/
char* Py_TUF_urllib_urlretrieve(char* url) {
	char* fileLocation;
	PyObject *urllibMod;
	PyObject *args;
	PyObject* http_resp;
	PyObject* data;

	/* Load the urllib_tuf module ~ from tuf.interposition import urllib_tuf */
	urllibMod = PyImport_AddModule( "urllib_tuf" );
	if ( urllibMod == NULL ) {
		PyErr_Print();
		return NULL;
	}
	
	/* call ~ http_resp = tuf.interposition.urlretrieve( url ) 
	   This returns a tuple so I decided to return the /location/filename */
	http_resp = PyObject_CallMethod( urllibMod, (char *)"urlretrieve", "(s)", url );
	if ( http_resp == NULL ) {
		PyErr_Print();
		return NULL;
	}
	Py_XDECREF( urllibMod );
	
	
	data = PyTuple_GetItem( http_resp, 0 );
	if ( data == NULL ) {
		PyErr_Print();
		return NULL;
	}
	fileLocation = PyString_AsString( data );
	Py_XDECREF( data );
	
	return fileLocation;
}









//not tested
/*
* Method to call TUFs configure method. This function takes the JSON interposition filename
* as well as the parent repository directory and the parent ssl certificate directory, and
* configures TUF to interpose on update calls
*/
int Py_TUF_deconfigure(PyObject* tuf_config_obj) {
    // Init the python env
    Py_Initialize();
	PyObject *path;
	PyObject *currentDirectory;
	PyObject *tufInterMod;
	PyObject *configFunction;

	//import TUF module
	tufInterMod = PyImport_AddModule( "tuf.interposition" );
	if ( tufInterMod == NULL ) {
		PyErr_Print();
		return 0;
	}
	
	//get the configure function from tuf.interposition
	configFunction = PyObject_GetAttrString( tufInterMod, "deconfigure" );
	if ( configFunction == NULL ) {
		PyErr_Print();
		return 0;
	}
	Py_XDECREF( tufInterMod );

	//calls the config function from the tuf.interposition module
	//returns a dictionary with the configurations	
	//we are currently storing this globally 	
	configDict = PyObject_CallObject( configFunction, tuf_config_obj );

	//Py_XDECREF( arg0 );
	//Py_XDECREF( arg1 );
	//Py_XDECREF( arg2 );
	//Py_XDECREF( args );
	//Py_XDECREF( configFunction );

	if ( configDict == NULL ) {
		PyErr_Print();
		return 0;
	}

	printf( "TUF deconfigured.\n" );
	return 1;
}
