from tuf.libtuf import *
import os

repoPath   = "/tmp/gemsontuf/repository/"
clientPath = "/tmp/.gemtuf/client.staged/"

create_tuf_client_directory(repoPath, clientPath)
