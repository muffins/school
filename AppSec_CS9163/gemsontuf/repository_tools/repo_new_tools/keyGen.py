from tuf.libtuf import *
import os

secret_root_1 = "mysecret1"

secret_targets_1 = "mysecret4"

secret_release_1 = "mysecret6"

secret_timestamp_1 = "mysecret8"

secret_claimed_1 = "mysecret10"

secret_recent_1 = "mysecret12"

secret_unclaimed_1 = "mysecret14"

#key generate, they're all the same kind of
print "Generating keys"
generate_and_write_rsa_keypair("keys/root_key1",      bits=2048, password=secret_root_1)

generate_and_write_rsa_keypair("keys/targets_key1",   bits=2048, password=secret_targets_1)

generate_and_write_rsa_keypair("keys/release_key1",   bits=2048, password=secret_release_1)

generate_and_write_rsa_keypair("keys/timestamp_key1", bits=2048, password=secret_timestamp_1)

generate_and_write_rsa_keypair("keys/claimed_key1",   bits=2048, password=secret_claimed_1)

generate_and_write_rsa_keypair("keys/recent_key1",    bits=2048, password=secret_recent_1)

generate_and_write_rsa_keypair("keys/unclaimed_key1", bits=2048, password=secret_unclaimed_1)
