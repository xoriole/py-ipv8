import ctypes
import libnacl
import unittest
from os import urandom

from ipv8.keyvault import curve25519
from ipv8.keyvault.crypto import ECCrypto


class TestDoubleSign(unittest.TestCase):
    """
    Test whether two signatures can be exploited to derive the private key.
    """

    def setUp(self):
        self.ec = ECCrypto()
        self.data = "".join([chr(i) for i in range(256)])
        self.key = self.ec.generate_key(u"very-low")
        key_bin = "4c69624e61434c534b3a9fab25fdea70f6ffb9185fabf26f1d6c7d796e989" \
                  "dcaf083a900501e263c526898bbd08da7895dae4b72d0d216c8a0fcfcea34" \
                  "98c0871e651ac13562db445098"
        self.key = self.ec.key_from_private_bin(key_bin.decode('hex'))

    def test_key_generation(self):
        """
        Test if DH-shared secret generation is consistent.
        """
        a = urandom(32)
        a_pub = curve25519.scalarmult_base(a)

        b = urandom(32)
        b_pub = curve25519.scalarmult_base(b)

        ab = (curve25519.unpack(a) * curve25519.unpack(b))
        base_point = curve25519.pack(9)
        k_ab_base = curve25519.scalarmult(curve25519.pack(ab), base_point)
        k_ab_base2 = curve25519.x_point(ab, base_point)
        print "kab base:", k_ab_base.encode('hex')
        print "kab base:", k_ab_base2.encode('hex')

        # perform Diffie-Hellman computation for alice and bob
        k_ab = curve25519.scalarmult(a, b_pub)
        k_ba = curve25519.scalarmult(b, a_pub)

        print "k_ab :", k_ab.encode('hex')

        # keys should be the same
        assert k_ab == k_ba
        assert k_ab == k_ab_base

    def test_scalarmult_base(self):
        """
        Test scalar multiplication with base point is consistent with libnacl implementation.
        Using private key to derive public key as a test.
        """
        pub_libnacl = libnacl.crypto_scalarmult_base(self.key.key.sk)
        pub_ours = curve25519.scalarmult_base(self.key.key.sk)

        assert pub_libnacl == pub_ours

    def test_scalarmult(self):
        """
        Test scalar multiplication is consistent with libnacl implementation.
        """
        some_scalar = curve25519.pack(2)
        result_libnacl = self._libnacl_scalarmult(some_scalar, self.key.key.pk)
        result_ours = curve25519.scalarmult(some_scalar, self.key.key.pk)

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
        unpacked = curve25519.unpack(initial)
        packed = curve25519.pack(unpacked)
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

        # Compute 5P
        fiveP = curve25519.add_points(twoP, threeP)
        fiveP_expected = curve25519.x_point(5, P)

        assert fiveP == fiveP_expected

    def test_point_multiplication(self):
        """
        Test if scalar multiplication works if used multiple times.
        """
        P = self.key.key.pk

        two = curve25519.pack(2)
        twoP = curve25519.double_point(P)

        three = curve25519.pack(3)
        threeP = curve25519.x_point(3, P)

        six = curve25519.pack(6)
        sixP = curve25519.scalarmult(three, twoP)
        sixP_expected = curve25519.x_point(6, P)
        print "sixP:", sixP.encode('hex')
        print "sixP:", sixP_expected.encode('hex')
        assert sixP == sixP_expected

        eighteenP = curve25519.scalarmult(three, sixP)
        eighteenP2 = curve25519.scalarmult(six, threeP)
        eighteenP_expected = curve25519.x_point(18, P)

        assert eighteenP == eighteenP_expected
        assert eighteenP2 == eighteenP_expected

    def test_clamping(self):
        """
        Test clamping of scalars.
        """
        a = curve25519.unpack(urandom(32))
        a_clamped = curve25519.clamp(a)
        print "a:", curve25519.pack(a).encode('hex')
        print "a:", curve25519.pack(a_clamped).encode('hex'), "\n"

        b = curve25519.unpack(urandom(32))
        b_clamped = curve25519.clamp(b)
        print "b:", curve25519.pack(b).encode('hex')
        print "b:", curve25519.pack(b_clamped).encode('hex'), "\n"

        c0 = a * b
        c1 = a * b_clamped
        c2 = a_clamped * b
        c3 = a_clamped * b_clamped

        c_clamped0 = curve25519.clamp(c0)
        c_clamped1 = curve25519.clamp(c1)
        c_clamped2 = curve25519.clamp(c2)
        c_clamped3 = curve25519.clamp(c3)

        print "c0:", curve25519.pack(c0).encode('hex')
        print "c0:", curve25519.pack(c_clamped0).encode('hex'), "\n"
        print "c1:", curve25519.pack(c1).encode('hex')
        print "c1:", curve25519.pack(c_clamped1).encode('hex'), "\n"
        print "c2:", curve25519.pack(c2).encode('hex')
        print "c2:", curve25519.pack(c_clamped2).encode('hex'), "\n"
        print "c3:", curve25519.pack(c3).encode('hex')
        print "c3:", curve25519.pack(c_clamped3).encode('hex'), "\n"


    def test_scalar_multiplication(self):
        """
        Test if multiplication and addition is correct.
        """
        P = self.key.key.pk
        P = curve25519.scalarmult_base(self.key.key.sk)

        a = curve25519.pack(2)
        b = curve25519.pack(3)
        d = self.key.key.sk

        d_unpacked = curve25519.unpack(d)
        bd = 3 + d_unpacked

        sum_scalar = (2 + 3 * d_unpacked) % curve25519.P

        point_q = curve25519.scalarmult_base(curve25519.pack(sum_scalar))

        aG = curve25519.scalarmult_base(a)
        bP = curve25519.scalarmult(b, P)
        bP2 = curve25519.scalarmult_base(curve25519.pack(bd))

        print "bP:", bP.encode('hex')
        print "bP:", bP2.encode('hex')

        point_q2 = curve25519.add_points(aG, bP)
        point_q3 = curve25519.subtract_points(aG, bP)

        print "point q:", point_q.encode('hex')
        print "point q:", point_q2.encode('hex')
        print "point q:", point_q3.encode('hex')
        assert point_q == point_q2

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
        common_base = curve25519.pack(123456789)
        message = curve25519.pack(11111111111111111111111111111111111111)
        signature = curve25519.double_signature(self.key.key.sk, message, common_base)
        print "signature:", signature.encode('hex')

        # curve25519.verify_custom_signature(self.key.key.pk, message, signature, common_base)

    def test_double_signature(self):

        # Let r be derived from the common base
        r = 32
        r_packed = curve25519.pack(r)

        pointR = curve25519.scalarmult_base_unclamped(r_packed)

        # some deterministic hash
        H = 36

        # private key
        d = curve25519.clamp(curve25519.unpack(self.key.key.sk))

        # compute s
        s = (r + H * d) % curve25519.P

        PK = curve25519.scalarmult_base(self.key.key.sk)
        pointS = curve25519.scalarmult_base_unclamped(curve25519.pack(s))

        pointHP = curve25519.scalarmult_unclamped(curve25519.pack(H), PK)

        pointDiff = curve25519.subtract_points(pointS, pointR)

        pointAdd = curve25519.add_points(pointR, pointHP)

        print "HP  :", pointHP.encode('hex')
        print "Diff:", pointDiff.encode('hex')
        print "sum :", pointAdd.encode('hex')
        print "S   :", pointS.encode('hex')
