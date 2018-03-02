import logging
from binascii import unhexlify, hexlify

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.hashes import SHA256

from cryptography.hazmat.primitives.asymmetric import ec

from ipv8.keyvault.doublesign import SECP256k1
from ..keyvault.keys import Key
from .private.libnaclkey import LibNaCLSK
from .private.m2crypto import M2CryptoSK
from .public.libnaclkey import LibNaCLPK
from .public.m2crypto import M2CryptoPK

# We want to provide a few default curves.  We will change these curves as new become available and
# old ones to small to provide sufficient security.
_CURVES = {u"very-low": (ec.SECT163K1, "M2Crypto"),
           u"low": (ec.SECT233K1, "M2Crypto"),
           u"medium": (ec.SECT409K1, "M2Crypto"),
           u"high": (ec.SECT571R1, "M2Crypto"),
           u'curve25519': (None, "libnacl")}

logger = logging.getLogger(__name__)


class ECCrypto(object):
    """
    A crypto object which provides a layer between Dispersy and low level eccrypographic features.

    Most methods are implemented by:
        @author: Boudewijn Schoon
        @organization: Technical University Delft
        @contact: dispersy@frayja.com

    However since then, most functionality was completely rewritten by:
        @author: Niels Zeilemaker
    """
    def __init__(self):
        super(ECCrypto, self).__init__()
        self.ecdsa = SECP256k1()

    @property
    def security_levels(self):
        """
        Returns the names of all available curves.
        @rtype: [unicode]
        """
        return _CURVES.keys()

    def generate_key(self, security_level):
        """
        Generate a new Elliptic Curve object with a new public / private key pair.

        Security can be u'low', u'medium', or u'high' depending on how secure you need your Elliptic
        Curve to be.  Currently these values translate into:
            - very-low: NID_sect163k1  ~42 byte signatures
            - low:      NID_sect233k1  ~60 byte signatures
            - medium:   NID_sect409k1 ~104 byte signatures
            - high:     NID_sect571r1 ~144 byte signatures

        Besides these predefined curves, all other curves provided by M2Crypto are also available.  For
        a full list of available curves, see ec_get_curves().

        @param security_level: Level of security {u'very-low', u'low', u'medium', or u'high'}.
        @type security_level: unicode
        """
        if security_level not in _CURVES:
            raise RuntimeError("Illegal curve for key generation: %s" % security_level)

        curve = _CURVES[security_level]
        if curve[1] == "M2Crypto":
            return M2CryptoSK(curve[0])

        if curve[1] == "libnacl":
            return LibNaCLSK()

    def key_to_bin(self, ec):
        "Convert the key to a binary format."
        assert isinstance(ec, Key), ec
        return ec.key_to_bin()

    def key_to_hash(self, ec):
        "Get a hash representation from a key."
        assert isinstance(ec, Key), ec
        return ec.key_to_hash()

    def is_valid_private_bin(self, string):
        "Returns True if the input is a valid public/private keypair stored in a binary format"
        try:
            self.key_from_private_bin(string)
        except:
            return False
        return True

    def is_valid_public_bin(self, string):
        "Returns True if the input is a valid public key"
        try:
            self.key_from_public_bin(string)
        except:
            return False
        return True

    def key_from_private_bin(self, string):
        "Get the EC from a public/private keypair stored in a binary format."
        if string.startswith("LibNaCLSK:"):
            return LibNaCLSK(string[10:])
        return M2CryptoSK(keystring=string)

    def key_from_public_bin(self, string):
        "Get the EC from a public key in binary format."
        if string.startswith("LibNaCLPK:"):
            return LibNaCLPK(string[10:])
        return M2CryptoPK(keystring=string)

    def get_signature_length(self, ec):
        """
        Returns the length, in bytes, of each signature made using EC.
        """
        assert isinstance(ec, Key), ec
        return ec.get_signature_length()

    def create_signature(self, ec, data):
        """
        Returns the signature of DIGEST made using EC.
        """
        assert isinstance(ec, Key), ec
        assert isinstance(data, str), type(data)
        return ec.signature(data)

    def is_valid_signature(self, ec, data, signature):
        """
        Returns True when SIGNATURE matches the DIGEST made using EC.
        """
        assert isinstance(ec, Key), ec
        assert isinstance(data, str), type(data)
        assert isinstance(signature, str), type(signature)

        try:
            return ec.verify(signature, data)
        except:
            return False

    def create_custom_signature(self, ec, data, common_base):
        """
        Returns a Sec256k1 signature to prevent double spending.
        """
        msg_digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        msg_digest.update(data)
        digest1 = msg_digest.finalize()

        common_digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        common_digest.update(common_base)
        digest2 = common_digest.finalize()

        int_key = int(ec.key.hex_sk(), 16)
        int_digest = int(digest1.encode('hex'), 16)
        int_common = int(digest2.encode('hex'), 16)

        print "private key: %0x" % int_key

        (r,s) = self.ecdsa.sign(int_digest, int_key, int_common)
        signature = self.pack32(r.value)+self.pack32(s.value)
        return signature

    def verify_custom_signature(self, signature, data):
        length = len(signature) / 2
        r = self.unpack32(signature[:length])
        s = self.unpack32(signature[length:])

        msg_digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        msg_digest.update(data)
        digest1 = msg_digest.finalize()
        int_digest = int(digest1.encode('hex'), 16)

        pubkey = self.ecdsa.pubkey_from_signature(int_digest, r, s, 0)
        return self.ecdsa.verify(int_digest, pubkey, r, s)

    def recover_double_signature(self, signature1, signature2, data1, data2):
        if len(signature1) != len(signature2):
            print "Invalid signatures"
            return
        length = len(signature1)/2

        r1 = self.unpack32(signature1[:length])
        s1 = self.unpack32(signature1[length:])
        r2 = self.unpack32(signature2[:length])
        s2 = self.unpack32(signature2[length:])

        if r1 != r2:
            print "Cannot recover private key from these signatures (r1 =/= r2)"
            return

        data1_digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        data1_digest.update(data1)
        int_data1 = int(data1_digest.finalize().encode('hex'), 16)

        data2_digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        data2_digest.update(data2)
        int_data2 = int(data2_digest.finalize().encode('hex'), 16)

        (secret, private_key) = self.ecdsa.recover_from_double_signature(r1, s1, s2, int_data1, int_data2)
        print "secret:", secret
        print "private key:", private_key

    # Equivalent to RFC7748 decodeUCoordinate followed by decodeLittleEndian
    def unpack32(self, s):
        if len(s) != 32:
            raise ValueError('Invalid Curve25519 scalar (len=%d)' % len(s))
        t = sum(ord(s[i]) << (8 * i) for i in range(31))
        t += ((ord(s[31]) & 0x7f) << 248)
        return t


    def pack32(self, n):
        return ''.join([chr((n >> (8 * i)) & 255) for i in range(32)])