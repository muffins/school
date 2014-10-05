from tuf.libtuf import *
import hashlib

repository = load_repository("/tmp/gemsontuf/repository/")

secret_release_1   = "mysecret6"
secret_timestamp_1 = "mysecret8"
secret_recent_1    = "mysecret12"
secret_unclaimed_1 = "mysecret14"

publicRelease1 = import_rsa_publickey_from_file("keys/release_key1.pub")
publicTimestamp1 = import_rsa_publickey_from_file("keys/timestamp_key1.pub")
publicRecent1 = import_rsa_publickey_from_file("keys/recent_key1.pub")
publicUnclaimed1 = import_rsa_publickey_from_file("keys/unclaimed_key1.pub")

privateRelease1 = import_rsa_privatekey_from_file("keys/release_key1", secret_release_1)
privateTimestamp1 = import_rsa_privatekey_from_file("keys/timestamp_key1", secret_timestamp_1)
privateRecent1 = import_rsa_privatekey_from_file("keys/recent_key1", secret_recent_1)
privateUnclaimed1 = import_rsa_privatekey_from_file("keys/unclaimed_key1", secret_unclaimed_1)

repository.release.load_signing_key(privateRelease1)
repository.timestamp.load_signing_key(privateTimestamp1)
repository.targets.recent.load_signing_key(privateRecent1)

f = open("recentlyClaimed.txt", "r")

updateUnclaimed = {}
for files in f:
    files = files.rstrip('\n')
    sha = hashlib.sha256()
    sha.update(files)
    y = sha.hexdigest()

    num = int(y[0:3], 16)
    mod = num % 4
    num -= mod
    y = hex(num)
    y = y[2:]

    if len(y) == 1:
        y = "00" + y
    elif len(y) == 2:
        y = "0" + y

    tmp = getattr(repository.targets.unclaimed, y)
    try:
    	tmp.remove_target(files)
    	repository.targets.recent.add_target(files)
    	tmp.load_signing_key(privateUnclaimed1)
    	updateUnclaimed[y] = tmp
    except tuf.Error, e:
    	print e
    	pass

#I thought this happened on it's own sometimes?
#this is just updating the version number
for k in updateUnclaimed.keys():
    newVersion = updateUnclaimed[k]
    newVersion.version += 1
repository.targets.recent.version += 1
repository.release.version += 1
repository.timestamp.version += 1

print "Writing repository-stage"
try:
  repository.write()
except tuf.Error, e:
  print e