#!/usr/bin/env python

#
# Requires web.py
# To install do:
#     pip install web.py
#
# This server does not prevent caching
#
# To use with gem install/update:
#     gem install [gemfile] --source http://localhost:8080
#     gem update [gemfile] --source http://localhost:8080
#

import web
import tuf.interposition
from tuf.interposition import urllib2_tuf as urllib2

        
urls = (
    '(.*)', 'handler'
)
app = web.application(urls, globals())

class handler:        
    def GET(self, target):
        if not target: 
            raise web.notfound()
        else:
            try:
                return urllib2.urlopen("http://" + web.ctx.host + target)
            except Exception as inst:
                print "*** ERROR ***" + inst + "**********"
                raise web.notfound()

if __name__ == "__main__":
    tuf.interposition.configure()
    app.run()
