#include "python2.7/Python.h"
#include <stdbool.h>

bool Py_TUF_configure(char*, char*, char*);
bool Py_TUF_deconfigure(PyObject*);
char* Py_TUF_urllib_urlopen(char*);
bool Py_TUF_urllib2_urlopen(char*);
bool Py_TUF_urllib_urlretrieve(char*, char*);

 
