from tuf.libtuf import *
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

secret_root_1      = "mysecret1"
secret_targets_1   = "mysecret4"
secret_release_1   = "mysecret6"
secret_timestamp_1 = "mysecret8"
secret_claimed_1   = "mysecret10"
secret_recent_1    = "mysecret12"
secret_unclaimed_1 = "mysecret14"

repository = load_repository(repoPath)

#public key import
print "Importing keys"
publicRoot1 = import_rsa_publickey_from_file("keys/root_key1.pub")
publicTargets1 = import_rsa_publickey_from_file("keys/targets_key1.pub")
publicRelease1 = import_rsa_publickey_from_file("keys/release_key1.pub")
publicTimestamp1 = import_rsa_publickey_from_file("keys/timestamp_key1.pub")
publicClaimed1 = import_rsa_publickey_from_file("keys/claimed_key1.pub")
publicRecent1 = import_rsa_publickey_from_file("keys/recent_key1.pub")
publicUnclaimed1 = import_rsa_publickey_from_file("keys/unclaimed_key1.pub")

#private key import second parameter is so you don't have to type a password in
privateRoot1 = import_rsa_privatekey_from_file("keys/root_key1", password=secret_root_1)
privateTargets1 = import_rsa_privatekey_from_file("keys/targets_key1", password=secret_targets_1)
privateRelease1 = import_rsa_privatekey_from_file("keys/release_key1", password=secret_release_1)
privateTimestamp1 = import_rsa_privatekey_from_file("keys/timestamp_key1", password=secret_timestamp_1)
privateClaimed1 = import_rsa_privatekey_from_file("keys/claimed_key1", password=secret_claimed_1)
privateRecent1 = import_rsa_privatekey_from_file("keys/recent_key1", password=secret_recent_1)
privateUnclaimed1 = import_rsa_privatekey_from_file("keys/unclaimed_key1", password=secret_unclaimed_1)

#adds public keys to directory
repository.root.add_key(publicRoot1)
repository.targets.add_key(publicTargets1)
repository.release.add_key(publicRelease1)
repository.timestamp.add_key(publicTimestamp1)
repository.targets.claimed.add_key(publicClaimed1)
repository.targets.recent.add_key(publicRecent1)
repository.targets.unclaimed.add_key(publicUnclaimed1)

#create thresholds
repository.root.threshold = 1
repository.targets.threshold = 1
repository.release.threshold = 1
repository.timestamp.threshold = 1
repository.targets.claimed.threshold = 1
repository.targets.recent.threshold = 1
repository.targets.unclaimed.threshold = 1

#load singing keys
repository.root.load_signing_key(privateRoot1)
repository.targets.load_signing_key(privateTargets1)
repository.release.load_signing_key(privateRelease1)
repository.timestamp.load_signing_key(privateTimestamp1)
repository.targets.claimed.load_signing_key(privateClaimed1)
repository.targets.recent.load_signing_key(privateRecent1)
repository.targets.unclaimed.load_signing_key(privateUnclaimed1)

#might create repository in this file and the update will update the repository instead
#targets = repository.get_filepaths_in_directory("./repository/targets/", True)

y = 0
pref_size = -(-(BINBITS+BINSIZEBITS) // 4)  #ceiling division trick http://bit.ly/18yuUBI
percent = (2**(BINBITS-1)) 
step = (2**(BINSIZEBITS+1))
print "Generating bins"
while y < (BINSIZE*BINS):
    prefix = []
    for k in range(y, y + BINSIZE):
        a = hex(k)
        pre = a[2:] #remove "0x"
        pre = pre.zfill(pref_size)

        prefix.append(pre)

    delName = hex(y)
    delName = delName[2:].zfill(pref_size)

    repository.targets.unclaimed.delegate(delName, [publicUnclaimed1], [], 1, None, prefix)
    tmp = getattr(repository.targets.unclaimed, delName)
    tmp.load_signing_key(privateUnclaimed1)

    if y % percent == 0:
        print 100*y/(percent*step), "% complete"
    y += BINSIZE
print "100 % complete"

#prints some information about the repository setup
#repository.status()

#tries to create repository 
print "Writing repository-stage"
try:
  repository.write()
except tuf.Error, e:
  print e 


