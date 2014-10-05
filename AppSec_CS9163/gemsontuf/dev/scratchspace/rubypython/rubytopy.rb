require "rubygems"
require "rubypython"

RubyPython.start # start the Python interpreter

httplib = RubyPython.import("urllib")
print httplib.urlopen("http://google.com").read()

RubyPython.stop # stop the Python interpreter