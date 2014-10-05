#!/usr/bin/env ruby

# Use this simple server with gem to install the gems in repository/targets
# Usage:
#     gem install gemname --source http://localhost:9294
#
# To also avoid contacting rubygems.org or any other source, do:
#     gem sources --list
#     gem sources --remove [each source in list] 
#
# This server does not prevent caching
#

require 'webrick'
server = WEBrick::HTTPServer.new :Port => 9294
server.mount "/", WEBrick::HTTPServlet::FileHandler, './repository/'
trap('INT') { server.stop }
server.start
