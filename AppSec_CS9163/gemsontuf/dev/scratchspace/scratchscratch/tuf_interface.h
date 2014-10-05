#include "python2.7/Python.h"

#ifndef TUF_INTERFACE_H_
#define TUF_INTERFACE_H_

extern int _fileLength;

/* TUF Configure function.  Takes <Path to tuf.interposition.json>, <>, <> */
int Py_TUF_configure(char*, char*, char*);
/* TUF Deconfigure function.  Takes a <TUF Configure> object as it's only argument */
int Py_TUF_deconfigure(PyObject*);
/* urllib_tuf urlopen() function.  Takes a URL to open and returns the data retrieved as a char* */
char* Py_TUF_urllib_urlopen(char*);
/* urllib_tuf urlretrieve() function.  Takes a URL to fetch and stores it in /tmp/.  The file name is returned as a char* */
char* Py_TUF_urllib_urlretrieve(char*);
/* urllib2_tuf urlopen() function.  Takes a URL to open and returns the data retrieved as a char* */
char* Py_TUF_urllib2_urlopen(char*);

#endif TUF_INTERFACE_H_
