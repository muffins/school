.PHONY: clean stage unclaimed release all update link

stage:
	@echo "Generating repository"
	@mkdir -p repository
	@ln -s /tmp/gemsontuf/repository/targets repository/targets
	@python repoGen.py --project /tmp/gemsontuf/repository/targets/

unclaimed:
	@echo "Delegating unclaimed targets"
	@python delegate_unclaimed.py

release:
	@echo "Copying files"
	@rm -rf /tmp/gemsontuf/repository/metadata/ /tmp/gemsontuf/repository/config.cfg
	@mv repository/metadata/ repository/config.cfg /tmp/gemsontuf/repository/
	@rm -rf /tmp/.gemtuf/client/
	@mv client/ /tmp/.gemtuf/

link:
	@ln -s /tmp/gemsontuf/repository/metadata repository/metadata

update: link unclaimed

all: stage unclaimed release

clean:
	rm -rf *~ tuf.log keystore client repository *.pyc
