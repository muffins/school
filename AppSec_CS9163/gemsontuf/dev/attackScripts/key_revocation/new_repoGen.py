from tuf.libtuf import *
import os

secret_root_1 = "mysecret1"
secret_root_2 = "mysecret2"
secret_root_3 = "mysecret3"

secret_targets_1 = "new_mysecret4"
secret_targets_2 = "new_mysecret5"

secret_release_1 = "mysecret6"
secret_release_2 = "mysecret7"

secret_timestamp_1 = "mysecret8"
secret_timestamp_2 = "mysecret9"

repoPath = "/tmp/gemsontuf/dev/attackScripts/key_revocation/repository/"

#public key import
print "Importing keys"
publicRoot1 = import_rsa_publickey_from_file("keys/root_key1.pub")
publicRoot2 = import_rsa_publickey_from_file("keys/root_key2.pub")
publicRoot3 = import_rsa_publickey_from_file("keys/root_key3.pub")

publicTargets1 = import_rsa_publickey_from_file("keys/new_targets_key1.pub")
publicTargets2 = import_rsa_publickey_from_file("keys/new_targets_key2.pub")

publicRelease1 = import_rsa_publickey_from_file("keys/release_key1.pub")
publicRelease2 = import_rsa_publickey_from_file("keys/release_key2.pub")

publicTimestamp1 = import_rsa_publickey_from_file("keys/timestamp_key1.pub")
publicTimestamp2 = import_rsa_publickey_from_file("keys/timestamp_key2.pub")

#private key import second parameter is so you don't have to type a password in
privateRoot1 = import_rsa_privatekey_from_file("keys/root_key1", password=secret_root_1)
privateRoot2 = import_rsa_privatekey_from_file("keys/root_key2", password=secret_root_2)
privateRoot3 = import_rsa_privatekey_from_file("keys/root_key3", password=secret_root_3)

privateTargets1 = import_rsa_privatekey_from_file("keys/new_targets_key1", password=secret_targets_1)
privateTargets2 = import_rsa_privatekey_from_file("keys/new_targets_key2", password=secret_targets_2)

privateRelease1 = import_rsa_privatekey_from_file("keys/release_key1", password=secret_release_1)
privateRelease2 = import_rsa_privatekey_from_file("keys/release_key2", password=secret_release_2)

privateTimestamp1 = import_rsa_privatekey_from_file("keys/timestamp_key1", password=secret_timestamp_1)
privateTimestamp2 = import_rsa_privatekey_from_file("keys/timestamp_key2", password=secret_timestamp_2)

#create new repository directory
print "Building repository"
repository = create_new_repository(repoPath)

#adds public keys to directory
repository.root.add_key(publicRoot1)
repository.root.add_key(publicRoot2)
repository.root.add_key(publicRoot3)

repository.targets.add_key(publicTargets1)
repository.targets.add_key(publicTargets2)

repository.release.add_key(publicRelease1)
repository.release.add_key(publicRelease2)

repository.timestamp.add_key(publicTimestamp1)
repository.timestamp.add_key(publicTimestamp2)

#create thresholds
repository.root.threshold = 3
repository.targets.threshold = 2
repository.release.threshold = 2
repository.timestamp.threshold = 2

#load singing keys
repository.root.load_signing_key(privateRoot1)
repository.root.load_signing_key(privateRoot2)
repository.root.load_signing_key(privateRoot3)

repository.targets.load_signing_key(privateTargets1)
repository.targets.load_signing_key(privateTargets2)

repository.release.load_signing_key(privateRelease1)
repository.release.load_signing_key(privateRelease2)

repository.timestamp.load_signing_key(privateTimestamp1)
repository.timestamp.load_signing_key(privateTimestamp2)

#expiration date
repository.timestamp.expiration = "2014-10-10 12:00:00"

#set compression mode
repository.targets.compressions = ["gz"]
repository.release.compressions = ["gz"]

#Add new targets
print "Building targets file"
targetFiles = repository.get_filepaths_in_directory(repoPath + "targets/", recursive_walk=True, followlinks=True)
repository.targets.add_targets(targetFiles)

#prints some information about the repository setup
repository.status()

#tries to create repository 
print "Writing repository-stage"
try:
  repository.write()
except tuf.Error, e:
  print e 


