require "rubygems"
require "rubypython"

RubyPython.start # start the Python interpreter

tuf = RubyPython.import("tuf.interposition")
httplib = RubyPython.import("urllib_tuf")
tuf.configure()
print httplib.urlopen("http://localhost:8080/gems/arbitrary-0.0.6.gem").read()

RubyPython.stop # stop the Python interpreter