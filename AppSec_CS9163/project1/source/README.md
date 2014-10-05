AppSec_CS9163
=============

This repo contains the projects for the Application Security Class, 
CS 9163, at NYU Polytechnic, Fall 2013

To compile this project, simply type:

    make

This will verify that the file 'sandbox.py' is in the current working
directory before the user attempts to run the script.

To run a file, for example the fibonacci program, simply type

    python sandbox.py fibo.in

At the command line, and the sandbox will run the program handed to it
in the first command line argument.  Note that these programs do not
need to have the '.in' suffix, this is simply a convention used to
distinguish scripts for the user.
