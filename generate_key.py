from __future__ import absolute_import
from __future__ import print_function

from binascii import hexlify

from ipv8.keyvault.crypto import ECCrypto

# This script generates a list of different curve keys and prints it in hex format
from ipv8.util import cast_to_bin

print("IPv8 Key generation")
print("\nVery Low")
print(hexlify(ECCrypto().generate_key(u"very-low").pub().key_to_bin()))
print("\nLow")
print(hexlify(ECCrypto().generate_key(u"low").pub().key_to_bin()))
print("\nMedium")
print(hexlify(ECCrypto().generate_key(u"medium").pub().key_to_bin()))
print("\nHigh")
print(hexlify(ECCrypto().generate_key(u"high").pub().key_to_bin()))
print("\nCurve25519")
print(hexlify(ECCrypto().generate_key(u"curve25519").pub().key_to_bin()))

ec = ECCrypto()
data = cast_to_bin("".join([chr(i) for i in range(256)]))

key_types = [u"very-low", u"low", u"medium", u"high", u"curve25519"]
for key_type in key_types:
    key = ec.generate_key(key_type)
    signature = key.signature(data)
    print(key_type, "  :", ec.is_valid_signature(key.pub(), data, signature))
