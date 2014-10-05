.PHONY: clean stage

stage:
	@mkdir keys
	@chmod 700 keys
	python keyGen.py
	python repoGen.py
	rm -rf /tmp/gemsontuf/repository/metadata/
	mv /tmp/gemsontuf/repository/metadata.staged/ /tmp/gemsontuf/repository/metadata/
	python clientGen.py
	rm -rf /tmp/.gemtuf/client/
	mv /tmp/.gemtuf/client.staged /tmp/.gemtuf/client

clean:
	rm -rf *~ tuf.log keys
