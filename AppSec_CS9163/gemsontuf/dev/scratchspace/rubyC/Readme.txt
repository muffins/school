How to test via interactive ruby (irb):
1. "irb -I"
2. "require './GemsOnTuf.so'"
3. "tuf = GemsOnTuf::TUF.new("/home/panhchan/workspace/Assignment3/gemsontuf/scratchspace/tuf.interposition.json","","")"
4. "url ="https://rubygems.org/latest_specs.4.8.gz""
5. "data = tuf.urlOpen(url)"

How to test remote_fetcher.rb:

1. Compile tuf_interface.c as directed: gcc tuf_interface.c -o tuf_interface -lpython2.7
  NOTE: After main() was removed, compile with: gcc -fPIC -c tuf_interface.c -lpython2.7
2. Make GemsOnTuf accordingly: "ruby extconf.rb" then "make"
3. Put all of the above files in same directory.
4. Edit "require '/path/to/GemsOnTuf.so'" accordingly.
5. Edit line 248 "tuf = GemsOnTuf::TUF.new(filename="/path/to/tuf.interposition.json","./","./")" accordingly.
6. Copy the modified remote_fetcher.rb into the rubygems working directory:
	sudo cp remote_fetcher.rb /usr/local/lib/site_ruby/1.9.1/rubygems
7. Test gems accordingly.

My (Pan) results as of 11/11/2013 11:50PM:
I followed the procedure as I outlined above.
The repository located on github was being hosted locally using "python -m SimpleHTTPServer"
Executing "sudo gem install arbitrary-0.6.6" did work properly for the most part:
What it DID do:
	- Sources is set to rubygems.org but TUF interposition intercepted and redirected to localhost:8000 (where my repo was hosted)
	- Local server did show gem asking for the right files:
		localhost - - [11/Nov/2013 20:56:41] "GET /metadata/timestamp.txt HTTP/1.1" 200 -
		localhost - - [11/Nov/2013 20:56:41] "GET /targets/latest_specs.4.8.gz HTTP/1.1" 200 -
		localhost - - [11/Nov/2013 20:56:41] "GET /metadata/timestamp.txt HTTP/1.1" 200 -
		localhost - - [11/Nov/2013 20:56:41] "GET /metadata/timestamp.txt HTTP/1.1" 200 -
		localhost - - [11/Nov/2013 20:56:41] "GET /targets/prerelease_specs.4.8.gz HTTP/1.1" 200 -
		localhost - - [11/Nov/2013 20:56:41] "GET /metadata/timestamp.txt HTTP/1.1" 200 -
		localhost - - [11/Nov/2013 20:56:41] "GET /metadata/timestamp.txt HTTP/1.1" 200 -
		localhost - - [11/Nov/2013 20:56:41] "GET /targets/specs.4.8.gz HTTP/1.1" 200 -
		localhost - - [11/Nov/2013 20:56:41] "GET /metadata/timestamp.txt HTTP/1.1" 200 -
What went WRONG:
	- Our C-Bridge did not pass back a value rubygems expected:
		ERROR:  Could not find a valid gem 'arbitrary-0.0.6' (>= 0), here is why:
        Unable to download data from https://rubygems.org - server did not return a valid file (https://rubygems.org/latest_specs.4.8.gz)


FULL ERROR DUMP:
panhchan@ubuntu:~/workspace/Assignment3/gemsontuf/scratchspace$ sudo gem install arbitrary-0.0.6
TUF configured.
test
Traceback (most recent call last):
  File "/usr/local/lib/python2.7/dist-packages/tuf/interposition/__init__.py", line 280, in configure
    parent_ssl_certificates_directory=parent_ssl_certificates_directory)
  File "/usr/local/lib/python2.7/dist-packages/tuf/interposition/__init__.py", line 206, in __read_configuration
    configuration_handler(configuration)
  File "/usr/local/lib/python2.7/dist-packages/tuf/interposition/updater.py", line 254, in add
    repository_mirror_hostnames = self.__check_configuration_on_add(configuration)
  File "/usr/local/lib/python2.7/dist-packages/tuf/interposition/updater.py", line 225, in __check_configuration_on_add
    assert configuration.hostname not in self.__updaters
AssertionError
test
ERROR:  Could not find a valid gem 'arbitrary-0.0.6' (>= 0), here is why:
          Unable to download data from https://rubygems.org - server did not return a valid file (https://rubygems.org/latest_specs.4.8.gz)
Traceback (most recent call last):
  File "/usr/local/lib/python2.7/dist-packages/tuf/interposition/__init__.py", line 280, in configure
    parent_ssl_certificates_directory=parent_ssl_certificates_directory)
  File "/usr/local/lib/python2.7/dist-packages/tuf/interposition/__init__.py", line 206, in __read_configuration
    configuration_handler(configuration)
  File "/usr/local/lib/python2.7/dist-packages/tuf/interposition/updater.py", line 254, in add
    repository_mirror_hostnames = self.__check_configuration_on_add(configuration)
  File "/usr/local/lib/python2.7/dist-packages/tuf/interposition/updater.py", line 225, in __check_configuration_on_add
    assert configuration.hostname not in self.__updaters
AssertionError
test
Traceback (most recent call last):
  File "/usr/local/lib/python2.7/dist-packages/tuf/interposition/__init__.py", line 280, in configure
    parent_ssl_certificates_directory=parent_ssl_certificates_directory)
  File "/usr/local/lib/python2.7/dist-packages/tuf/interposition/__init__.py", line 206, in __read_configuration
    configuration_handler(configuration)
  File "/usr/local/lib/python2.7/dist-packages/tuf/interposition/updater.py", line 254, in add
    repository_mirror_hostnames = self.__check_configuration_on_add(configuration)
  File "/usr/local/lib/python2.7/dist-packages/tuf/interposition/updater.py", line 225, in __check_configuration_on_add
    assert configuration.hostname not in self.__updaters
AssertionError
test
Traceback (most recent call last):
  File "/usr/local/lib/python2.7/dist-packages/tuf/interposition/__init__.py", line 280, in configure
    parent_ssl_certificates_directory=parent_ssl_certificates_directory)
  File "/usr/local/lib/python2.7/dist-packages/tuf/interposition/__init__.py", line 206, in __read_configuration
    configuration_handler(configuration)
  File "/usr/local/lib/python2.7/dist-packages/tuf/interposition/updater.py", line 254, in add
    repository_mirror_hostnames = self.__check_configuration_on_add(configuration)
  File "/usr/local/lib/python2.7/dist-packages/tuf/interposition/updater.py", line 225, in __check_configuration_on_add
    assert configuration.hostname not in self.__updaters
AssertionError
test
Traceback (most recent call last):
  File "/usr/local/lib/python2.7/dist-packages/tuf/interposition/__init__.py", line 280, in configure
    parent_ssl_certificates_directory=parent_ssl_certificates_directory)
  File "/usr/local/lib/python2.7/dist-packages/tuf/interposition/__init__.py", line 206, in __read_configuration
    configuration_handler(configuration)
  File "/usr/local/lib/python2.7/dist-packages/tuf/interposition/updater.py", line 254, in add
    repository_mirror_hostnames = self.__check_configuration_on_add(configuration)
  File "/usr/local/lib/python2.7/dist-packages/tuf/interposition/updater.py", line 225, in __check_configuration_on_add
    assert configuration.hostname not in self.__updaters
AssertionError
test
