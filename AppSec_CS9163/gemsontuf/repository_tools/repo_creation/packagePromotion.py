# Place holder script for promoting packages.
#
# This script will be used to transition a package between the
# security roles.  If a package is unclaimed this script should
# promote it to newly claimed, given all of the dev keys have been
# submitted.  If the package is recently claimed this script
# should transition the package to claimed given that the rugygems
# devs have vetted the package developers certs.


import sys, os



def main(pkg_name, role):
	pass

if __name__ == "__main__":
	if(len(sys.argv) == 3 and sys.argv[1] != "" and sys.argv[2] != ""):
		main(sys.argv[1], sys.argv[2])
	else:
		print("Usage: python %s <Package to Promote> <claimed/unclaimed/recently claimed>")
		sys.exit()
