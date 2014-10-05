from tuf.libtuf import *
import hashlib

repository = load_repository("/tmp/gemsontuf/repository/")

secret_release_1   = "mysecret6"
secret_timestamp_1 = "mysecret8"
secret_recent_1    = "mysecret12"
secret_claimed_1   = "mysecret10"

privateRelease1 = import_rsa_privatekey_from_file("keys/release_key1", secret_release_1)
privateTimestamp1 = import_rsa_privatekey_from_file("keys/timestamp_key1", secret_timestamp_1)
privateRecent1 = import_rsa_privatekey_from_file("keys/recent_key1", secret_recent_1)
privateClaimed1 = import_rsa_privatekey_from_file("keys/claimed_key1", secret_claimed_1)

repository.release.load_signing_key(privateRelease1)
repository.timestamp.load_signing_key(privateTimestamp1)
repository.targets.recent.load_signing_key(privateRecent1)
repository.targets.claimed.load_signing_key(privateClaimed1)

f = open("claimed.txt", "r")

for files in f:
    files = files.rstrip('\n')
    try:
        repository.targets.recent.remove_target(files)
        repository.targets.claimed.add_target(files)
    except tuf.Error, e:
        print e
        pass
    
#I thought this happened on it's own sometimes?
#this is just updating the version number
repository.targets.recent.version += 1
repository.targets.claimed.version += 1
repository.release.version += 1
repository.timestamp.version += 1

print "Writing repository-stage"
try:
  repository.write()
except tuf.Error, e:
  print e