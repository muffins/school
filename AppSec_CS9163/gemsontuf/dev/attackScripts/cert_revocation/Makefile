.PHONY: clean stage orig

stage:
	@mkdir keys
	@chmod 700 keys
	python keyGen.py
	python repoGen.py
	mv repository/metadata.staged/ repository/metadata.orig
	cp malicious.gem repository/targets/gems/arbitrary-0.0.6.gem

orig:
	rm -rf repository/metadata
	mv repository/metadata.orig/ repository/metadata/
	python clientGen.py
	rm -rf /tmp/.gemtuf/client/
	mv /tmp/.gemtuf/client.staged /tmp/.gemtuf/client


clean:
	rm -rf *~ tuf.log keys repository/metadata*
	cp repository/targets/gems/arbitrary-0.0.6.gem-copy repository/targets/gems/arbitrary-0.0.6.gem
