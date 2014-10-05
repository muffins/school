.PHONY: all tuf rubygems bridge setup msg local remote

msg:
	@echo "** Welcome to Gems on TUF installer **\n"
	@echo "1) To download and install TUF type:"
	@echo "\tmake tuf\n"
	@echo "2) To download the rubygems source using git type:"
	@echo "\tmake rubygems\n"
	@echo "3) To compile the Ruby to TUF bridge C library type:"
	@echo "\tmake bridge\n"
	@echo "4) To install Gems on TUF to /tmp dir, type:"
	@echo "\tmake setup\n"
	@echo "5) To use a local mirror instead of remote, type:"
	@echo "\tmake local\n"
	@echo "6) To use the remote mirror again, type:"
	@echo "\tmake remote\n"
	@echo "\nThank you for trying Gems on TUF"

all: tuf rubygems bridge setup


tuf:
	pip install tuf
	pip install --upgrade https://github.com/theupdateframework/tuf/archive/repository-tools.zip

rubygems:
	if test -d rubygems; then \
	  cd rubygems && git pull; \
	else \
	  git clone https://github.com/rubygems/rubygems.git; \
	fi

bridge:
	cd interface; ruby extconf.rb; make; cp GemsOnTuf.so ..; make clean; rm Makefile; cd ..

setup:
	@echo "Overwriting remote_fetcher.rb inside installation directory"
	cp remote_fetcher.rb rubygems/lib/rubygems
	@echo "Running gem setup"
	cd rubygems; ruby setup.rb; cd ..
	@echo "Creating .gemtuf directory in /tmp directory"
	mkdir -p /tmp/.gemtuf
	@echo "Saving gem_tuf.json and GemsOnTuf.so inside /tmp/.gemtuf directory"
	cp mirror.json /tmp/.gemtuf/gem_tuf.json
	cp GemsOnTuf.so /tmp/.gemtuf
	@echo "Saving ./client directory inside /tmp/.gemtuf directory"
	cp -r client /tmp/.gemtuf

local:
	cp local.json /tmp/.gemtuf/gem_tuf.json

remote:
	cp mirror.json /tmp/.gemtuf/gem_tuf.json

clean:
	rm -rf rubygems
	rm -f tuf.log GemsOnTuf.so
	rm -rf /tmp/.gemtuf

