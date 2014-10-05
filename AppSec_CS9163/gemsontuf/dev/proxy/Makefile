.PHONY: all prereqs webpy tuf rubygems setup

all: prereqs setup

prereqs: webpy tuf rubygems

webpy:
	pip install web.py

tuf:
	pip install tuf

rubygems:
	git clone https://github.com/rubygems/rubygems.git

setup:
	@echo "Overwriging gem inside bin directory"
	cp gem rubygems/bin
	@echo "Running gem setup"
	cd rubygems; ruby setup.rb; cd ..
	@echo "Creating .gemtuf directory in ~/ directory"
	mkdir -p ~/.gemtuf
	@echo "Saving gem_tuf.json inside ~/.gemtuf directory"
	cp gem_tuf.json ~/.gemtuf
	sed -i.bak 's/HOME/\/home\/$(USER)/g' ~/.gemtuf/gem_tuf.json
	@echo "Saving ./client directory inside ~/.gemtuf directory"
	cp -r client ~/.gemtuf
	@echo "Overwriting ~/.gemrc with one using localhost:8080"
	cp gemrc ~/.gemrc
	@echo "Saving tuf-proxy.py into gem bin directory"
	cp tuf-proxy.py $(shell dirname $(shell which gem))

clean:
	rm -rf rubygems
	rm -f $(dirname $(which gem))/tuf-proxy.py*
	rm -f tuf.log
	rm -rf ~/.gemtuf

