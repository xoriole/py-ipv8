import libnacl
import libnacl.dual
import libnacl.sign

from cryptography.hazmat.primitives.asymmetric.rsa import _modinv

from ...keyvault.public.libnaclkey import LibNaCLPK
from ...keyvault.keys import PrivateKey


class LibNaCLSK(PrivateKey, LibNaCLPK):
    """
    A LibNaCL implementation of a secret key.
    """

    def __init__(self, binarykey=""):
        """
        Create a new LibNaCL secret key. Optionally load it from a string representation.
        Otherwise generate it from the 25519 curve.

        :param binarykey: load the sk from this string (see key_to_bin())
        """
        # Load the key, if specified
        if binarykey:
            crypt, seed = binarykey[:libnacl.crypto_box_SECRETKEYBYTES], \
                          binarykey[libnacl.crypto_box_SECRETKEYBYTES :
                                    libnacl.crypto_box_SECRETKEYBYTES + libnacl.crypto_sign_SEEDBYTES]
            self.key = libnacl.dual.DualSecret(crypt, seed)
        else:
            self.key = libnacl.dual.DualSecret()
        # Immediately create a verifier
        self.veri = libnacl.sign.Verifier(self.key.hex_vk())

    def pub(self):
        """
        Get the public key for this secret key.
        """
        return LibNaCLPK(pk=self.key.pk, hex_vk=self.veri.hex_vk())

    def signature(self, msg):
        """
        Create a signature for a message.

        :param msg: the message to sign
        :return: the signature for the message
        """
        return self.key.signature(msg)

    def key_to_bin(self):
        """
        Get the string representation of this key.
        """
        return "LibNaCLSK:" + self.key.sk + self.key.seed

    def custom_signature(self, msg, leaker_prefix_bin):
        """
        Create a signature for a message.

        :param msg: the message to sign
        :return: the signature for the message
        """

        num_q = 2 ** 255 - 19

        int_msg1 = int(msg.encode('hex'), 16)

        k = leaker_prefix_bin.decode('hex')
        int_k = int(leaker_prefix_bin.encode('hex'), 16) % num_q
        # libnacl.randombytes(libnacl.crypto_scalarmult_SCALARBYTES)

        point_k = libnacl.crypto_scalarmult_base(k)

        r = int(point_k.encode('hex'), 16) % num_q

        d = int(self.key.hex_sk(), 16)

        s1 = (_modinv(int_k, num_q) * (int_msg1 + r * d)) % num_q

        return "%0x%0x" % (r, s1)

    def verify_custom_signature(self, msg, signature):
        """

        :param msg:
        :param signature:
        :return:
        """
        pass
