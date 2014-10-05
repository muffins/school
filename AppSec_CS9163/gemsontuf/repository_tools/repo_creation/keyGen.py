from tuf.libtuf import *
import os

secret_root_1 = "mysecret1"
secret_root_2 = "mysecret2"
secret_root_3 = "mysecret3"

secret_targets_1 = "mysecret4"
secret_targets_2 = "mysecret5"

secret_release_1 = "mysecret6"
secret_release_2 = "mysecret7"

secret_timestamp_1 = "mysecret8"
secret_timestamp_2 = "mysecret9"

#key generate, they're all the same kind of
print "Generating keys"
generate_and_write_rsa_keypair("keys/root_key1",      bits=2048, password=secret_root_1)
generate_and_write_rsa_keypair("keys/root_key2",      bits=2048, password=secret_root_2)
generate_and_write_rsa_keypair("keys/root_key3",      bits=2048, password=secret_root_3)

generate_and_write_rsa_keypair("keys/targets_key1",   bits=2048, password=secret_targets_1)
generate_and_write_rsa_keypair("keys/targets_key2",   bits=2048, password=secret_targets_2)

generate_and_write_rsa_keypair("keys/release_key1",   bits=2048, password=secret_release_1)
generate_and_write_rsa_keypair("keys/release_key2",   bits=2048, password=secret_release_2)

generate_and_write_rsa_keypair("keys/timestamp_key1", bits=2048, password=secret_timestamp_1)
generate_and_write_rsa_keypair("keys/timestamp_key2", bits=2048, password=secret_timestamp_2)
