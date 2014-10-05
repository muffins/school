from tuf.libtuf import *
import hashlib
import sys

if len(sys.argv) < 2:
  BINBITS=10
  BINSIZEBITS=2
else:
  BINBITS=int(sys.argv[1])
  BINSIZEBITS=int(sys.argv[2])

BINSIZE=2**BINSIZEBITS
BINS=2**BINBITS

assert (((BINBITS+BINSIZEBITS) % 4) == 0),"Not all bin prefixes are generated!"

repoPath   = "/tmp/gemsontuf/repository/"
targetsPath = "/tmp/gemsontuf/repository/targets/"

secret_release_1   = "mysecret6"
secret_timestamp_1 = "mysecret8"
secret_unclaimed_1 = "mysecret14"

repository = load_repository(repoPath)

print "Importing keys"
#private key import second parameter is so you don't have to type a password in
privateRelease1 = import_rsa_privatekey_from_file("keys/release_key1", password=secret_release_1)
privateTimestamp1 = import_rsa_privatekey_from_file("keys/timestamp_key1", password=secret_timestamp_1)
privateUnclaimed1 = import_rsa_privatekey_from_file("keys/unclaimed_key1", password=secret_unclaimed_1)

#load singing keys
repository.release.load_signing_key(privateRelease1)
repository.timestamp.load_signing_key(privateTimestamp1)
repository.targets.unclaimed.load_signing_key(privateUnclaimed1)

#add targets
targets = repository.get_filepaths_in_directory(targetsPath, recursive_walk=True, followlinks=True)
print "Updating bins"
for target in targets:
    t = hashlib.sha256()
    t.update(target)
    y = t.hexdigest()

    pref_size = -(-(BINBITS+BINSIZEBITS) // 4)  #ceiling division trick http://bit.ly/18yuUBI
    num = int(y[0:pref_size], 16)
    mod = num % BINSIZE
    num -= mod
    y = hex(num)
    y = y[2:]				#remove "0x"

    y = y.zfill(pref_size)		#add leading zeros
    print target, y

    tmp = getattr(repository.targets.unclaimed, y)
    tmp.add_target(target)
    tmp.load_signing_key(privateUnclaimed1)

#prints some information about the repository setup
repository.status()

#tries to create repository 
print "Writing repository-stage"
try:
  repository.write()
except tuf.Error, e:
  print e 

