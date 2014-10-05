.PHONY: clean stage update test
BIN=10
SIZE=2

stage:
	@echo "Generating new repository"
	@rm -rf keys
	@mkdir keys
	@chmod 700 keys
	python keyGen.py
	@rm -rf /tmp/gemsontuf/repository/metadata/ /tmp/gemsontuf/repository/metadata.staged/
	@rm -rf repository
	@mkdir -p repository
	@ln -s /tmp/gemsontuf/repository/targets repository/targets
	@ln -s /tmp/gemsontuf/repository/metadata repository/metadata
	python repoGen.py
	@ln -s /tmp/gemsontuf/repository/metadata.staged repository/metadata.staged
	python unclaimed.py $(BIN) $(SIZE)
	@echo "Moving files"
	@mv /tmp/gemsontuf/repository/metadata.staged /tmp/gemsontuf/repository/metadata
	@rm -rf /tmp/.gemtuf/client.staged /tmp/.gemtuf/client
	python clientGen.py
	@rm -rf /tmp/.gemtuf/client/
	@mv /tmp/.gemtuf/client.staged /tmp/.gemtuf/client


update:
	@echo "Updating unclaimed targets"
	@mv /tmp/gemsontuf/repository/metadata /tmp/gemsontuf/repository/metadata.staged
	python updateUnclaimed.py $(BIN) $(SIZE)
	@mv /tmp/gemsontuf/repository/metadata.staged /tmp/gemsontuf/repository/metadata
	@rm -rf /tmp/.gemtuf/client.staged /tmp/.gemtuf/client
	python clientGen.py
	@rm -rf /tmp/.gemtuf/client/
	@mv /tmp/.gemtuf/client.staged /tmp/.gemtuf/client


test:
	@rm -rf tests
	@mkdir tests
	python genTest.py
	@rm -rf /tmp/gemsontuf/repository/targets/tests
	@mv tests /tmp/gemsontuf/repository/targets
	./runtests
	cat results.txt

clean:
	rm -rf *~ tuf.log keystore client repository *.pyc keys tests /tmp/gemsontuf/repository/targets/tests
