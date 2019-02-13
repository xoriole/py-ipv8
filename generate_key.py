from __future__ import absolute_import
from __future__ import print_function

from binascii import hexlify

from ipv8.keyvault.crypto import ECCrypto

# This script generates a list of different curve keys and prints it in hex format
from ipv8.util import cast_to_bin

ec = ECCrypto()
data = cast_to_bin("".join([chr(i) for i in range(256)]))

key_types = [u"very-low", u"low", u"medium", u"high", u"curve25519"]
for key_type in key_types:
    print("\nTesting key type  :", key_type)
    key = ec.generate_key(key_type)
    print("Generated Key     :", hexlify(key.pub().key_to_bin()))
    signature = key.signature(data)
    print("Signature         :", hexlify(signature))
    print("Signature is valid:", ec.is_valid_signature(key.pub(), data, signature) != False)

