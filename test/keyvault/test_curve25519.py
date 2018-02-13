import ctypes
import libnacl
import unittest
from os import urandom

from ipv8.keyvault import curve25519
from ipv8.keyvault.crypto import ECCrypto
from ipv8.keyvault.curve25519 import scalarmult_base, scalarmult, add_points, double_point, unpack, pack, x_point


class TestCurve25519(unittest.TestCase):
    """
    Test whether two signatures can be exploited to derive the private key.
    """

    def setUp(self):
        self.ec = ECCrypto()
        self.data = "".join([chr(i) for i in range(256)])
        key_bin = "4c69624e61434c534b3a9fab25fdea70f6ffb9185fabf26f1d6c7d796e989" \
                  "dcaf083a900501e263c526898bbd08da7895dae4b72d0d216c8a0fcfcea34" \
                  "98c0871e651ac13562db445098"
        self.key = self.ec.key_from_private_bin(key_bin.decode('hex'))

    def test_key_generation(self):
        """
        Test if DH-shared secret generation is consistent.
        """
        a = urandom(32)
        a_pub = scalarmult_base(a)

        b = urandom(32)
        b_pub = scalarmult_base(b)

        # perform Diffie-Hellman computation for alice and bob
        k_ab = scalarmult(a, b_pub)
        k_ba = scalarmult(b, a_pub)

        # keys should be the same
        assert k_ab == k_ba

    def test_scalarmult_base(self):
        """
        Test scalar multiplication with base point is consistent with libnacl implementation.
        Using private key to derive public key as a test.
        """
        pub_libnacl = libnacl.crypto_scalarmult_base(self.key.key.sk)
        pub_ours = scalarmult_base(self.key.key.sk)

        assert pub_libnacl == pub_ours

    def test_scalarmult(self):
        """
        Test scalar multiplication is consistent with libnacl implementation.
        """
        some_scalar = pack(2)
        result_libnacl = self._libnacl_scalarmult(some_scalar, self.key.key.pk)
        result_ours = scalarmult(some_scalar, self.key.key.pk)

        assert result_libnacl == result_ours

    def _libnacl_scalarmult(self, n, pk):
        '''
        Computes and returns the scalar product of a given group element pk and an
        integer "n".
        '''
        buf = ctypes.create_string_buffer(libnacl.crypto_scalarmult_BYTES)
        ret = libnacl.nacl.crypto_scalarmult(buf, n, pk)
        if ret:
            raise libnacl.CryptError('Failed to compute scalar product')
        return buf.raw

    def test_pack_unpack(self):
        """
        Test if byte-int pack unpack works.
        """
        initial = "%032x" % 2
        unpacked = unpack(initial)
        packed = pack(unpacked)
        assert packed == initial

    def test_y_calculation(self):
        """
        Test if y-coordinate derivation from affine x-coordinate.
        Using base point of Curve25519 for this test.
        """
        x = 9
        actual_y = 14781619447589544791020593568409986887264606134616475288964881837755586237401

        # Computed y value
        computed_y = curve25519.calculate_y(x)
        assert computed_y == actual_y

    def test_point_addition(self):
        """
        Test if point addition and doubling works correctly.
        """
        P = self.key.key.pk
        twoP = curve25519.double_point(P)

        # Compute 3P = P + 2P
        threeP = curve25519.add_points(P, twoP)

        # Get 3P from scalar multiplication
        threeP_expected = curve25519.x_point(3, P)

        assert threeP == threeP_expected

    def test_point_doubling(self):
        """
        Test if point doubling gives same result as adding twice.
        :return:
        """
        P = self.key.key.pk

        doubleP = curve25519.add_points(P, P)
        twiceP = curve25519.double_point(P)

        assert doubleP == twiceP

    def test_custom_signature(self):
        """
        Test custom signature verification
        """
        common_base = pack(123456789)
        message = pack(11111111111111111111111111111111111111)
        signature = curve25519.custom_signature(self.key.key.sk, message, common_base)
        print "signature:", signature.encode('hex')

        curve25519.verify_custom_signature(self.key.key.pk, message, signature, common_base)
