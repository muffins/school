.PHONY: clean stage orig malicious

stage:
	@mkdir keys
	@chmod 700 keys
	python keyGen.py
	python repoGen.py
	mv repository/metadata.staged/ repository/metadata.orig
	cp malicious.gem repository/targets/gems/important-0.0.8.gem
	cp -r repository/metadata.orig/ repository/metadata.malicious 
	python repoGen.py
	mv repository/metadata.staged/targets.txt repository/metadata.malicious/targets.txt
	mv repository/metadata.staged/targets.txt.gz repository/metadata.malicious/targets.txt.gz
	rm -rf repository/metadata.staged
	cp repository/targets/gems/important-0.0.8.gem-copy repository/targets/gems/important-0.0.8.gem

orig:
	rm -rf repository/metadata
	mv repository/metadata.orig/ repository/metadata/
	python clientGen.py
	rm -rf /tmp/.gemtuf/client/
	mv /tmp/.gemtuf/client.staged /tmp/.gemtuf/client

malicious:
	rm -rf repository/metadata
	mv repository/metadata.malicious/ repository/metadata/
	python clientGen.py
	rm -rf /tmp/.gemtuf/client/
	mv /tmp/.gemtuf/client.staged /tmp/.gemtuf/client

clean:
	rm -rf *~ tuf.log keys repository/metadata*
	cp repository/targets/gems/important-0.0.8.gem-copy repository/targets/gems/important-0.0.8.gem
