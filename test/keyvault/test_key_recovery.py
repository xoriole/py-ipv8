import ctypes
import libnacl
import unittest
from os import urandom

from cryptography.hazmat.primitives.asymmetric.rsa import _modinv

from ipv8.keyvault import curve25519
from ipv8.keyvault.crypto import ECCrypto
from ipv8.keyvault.curve25519 import scalarmult_base, scalarmult, add_points, double_point
from ipv8.keyvault.private.libnaclkey import LibNaCLSK


class TestKeyRecovery(unittest.TestCase):
    """
    Test whether two signatures can be exploited to derive the private key.
    """

    def setUp(self):
        self.ec = ECCrypto()
        self.data = "".join([chr(i) for i in range(256)])

    def test_key_generation(self):
        # Private keys in Curve25519 can be any 32-byte string.
        a = urandom(32)
        a_pub = scalarmult_base(a)

        b = urandom(32)
        b_pub = scalarmult_base(b)

        # perform Diffie-Hellman computation for alice and bob
        k_ab = scalarmult(a, b_pub)
        k_ba = scalarmult(b, a_pub)

        # keys should be the same
        assert k_ab == k_ba

    def crypto_point_add(self, p1, p2):
        '''
        Computes and returns the scalar product of a standard group element and an
        integer "n".
        '''
        buf = ctypes.create_string_buffer(libnacl.crypto_scalarmult_BYTES)
        ret = libnacl.nacl.crypto_core_ed25519_add(buf, p1, p2)
        if ret:
            raise libnacl.CryptError('Failed to compute scalar product')
        return buf.raw

    def crypto_scalarmult(self, n, pk):
        '''
        Computes and returns the scalar product of a standard group element and an
        integer "n".
        '''
        buf = ctypes.create_string_buffer(libnacl.crypto_scalarmult_BYTES)
        ret = libnacl.nacl.crypto_scalarmult(buf, n, pk)
        if ret:
            raise libnacl.CryptError('Failed to compute scalar product')
        return buf.raw

    def ed_crypto_scalarmult_base(self, n):
        '''
        Computes and returns the scalar product of a standard group element and an
        integer "n".
        '''
        buf = ctypes.create_string_buffer(libnacl.crypto_scalarmult_BYTES)
        ret = libnacl.nacl.crypto_scalarmult_ed25519_base(buf, n)
        if ret:
            raise libnacl.CryptError('Failed to compute scalar product')
        return buf.raw

    def test_point_addition(self):
        test_key_bin = "4c69624e61434c534b3a9fab25fdea70f6ffb9185fabf26f1d6c7d796e989" \
                       "dcaf083a900501e263c526898bbd08da7895dae4b72d0d216c8a0fcfcea34" \
                       "98c0871e651ac13562db445098"
        key_bin = test_key_bin.decode('hex')
        # key = self.ec.generate_key(u"curve25519")
        key = self.ec.key_from_private_bin(test_key_bin.decode('hex'))
        # print "private key:", key.key.hex_sk()
        # print "public  key:", key.key.hex_pk()

        pub = libnacl.crypto_scalarmult_base(key.key.sk)
        pub_ed = self.ed_crypto_scalarmult_base(key.key.sk)
        print "priv: ", key.key.sk, type(key.key.sk)
        print "pub : ", key.key.pk, type(key.key.pk)
        print "pub:", pub.encode('hex')
        print "pub ed:", pub_ed.encode('hex')

        py_pub = scalarmult_base(key.key.sk)
        py_pub2 = scalarmult(key.key.sk, key.key.pk)
        print "pub:", py_pub.encode('hex')
        print "pub:", py_pub2.encode('hex')

        pub2 = add_points(key.key.pk, key.key.pk)
        pub3 = double_point(key.key.pk)
        print "pub + pub : ", pub2.encode('hex')
        print "pub + pub : ", pub3.encode('hex')

        two_bin = "0000000000000000000000000000000000000000000000000000000000000002".decode('hex')
        two_sk = 2 * int(key.key.sk.encode('hex'), 16) % curve25519.P
        two_sk_hex = ("%064x" % two_sk)
        print "two sk hex:", two_sk_hex
        two_sk_bin = "%s" % two_sk_hex



        pub2_mult = scalarmult(two_bin, key.key.pk)
        pub2_mult2 = libnacl.crypto_scalarmult_base(two_sk_bin)
        pub2_mult3 = self.crypto_scalarmult(two_bin, key.key.pk)
        pub2_mult4 = self.crypto_point_add(key.key.pk, key.key.pk)
        print "2 x pub : ", pub2_mult.encode('hex')
        print "2 x pub : ", pub2_mult2.encode('hex')
        print "2 x pub : ", pub2_mult3.encode('hex')
        print "2 x pub : ", pub2_mult4.encode('hex')


    def test_create_signature(self):
        test_key_bin = "4c69624e61434c534b3a9fab25fdea70f6ffb9185fabf26f1d6c7d796e989" \
                       "dcaf083a900501e263c526898bbd08da7895dae4b72d0d216c8a0fcfcea34" \
                       "98c0871e651ac13562db445098"
        key_bin = test_key_bin.decode('hex')
        key = self.ec.generate_key(u"curve25519")

        msg = "".join([chr(i) for i in range(255)])
        msg1 = msg + '0'
        msg2 = msg + '1'

        num_q = curve25519.P
        # k_bin = "4a0b1a5b4b2daf58a211cc39a5d3141ac615c62716d756e90c911673e03a7c4a".decode('hex')
        k_bin = "85d8dcc7b0defdcc5cb64116f5280df7935e0c027ef0332362dca385d00c7a50".decode('hex')
        # k = "9fab25fdea70f6ffb9185fabf26f1d6c7d796e989dcaf083a900501e263c5260".decode('hex')
        int_k = int(k_bin.encode('hex'), 16) % num_q

        signature = key.custom_signature(msg, k_bin)
        print "signature:", signature

        key.verify_custom_signature(msg, signature, key_bin)

    def test_curve25519(self):
        """
        Check if curve25519 keys can be recovered from two signatures with same k value
        """
        test_key_bin = "4c69624e61434c534b3a9fab25fdea70f6ffb9185fabf26f1d6c7d796e989" \
                       "dcaf083a900501e263c526898bbd08da7895dae4b72d0d216c8a0fcfcea34" \
                       "98c0871e651ac13562db445098"
        key_bin = test_key_bin.decode('hex')
        # key = self.ec.generate_key(u"curve25519")
        key = self.ec.key_from_private_bin(test_key_bin.decode('hex'))
        # print "private key:", key.key.hex_sk()
        # print "public  key:", key.key.hex_pk()

        pub = libnacl.crypto_scalarmult_base(key.key.sk)
        py_pub = scalarmult_base(key.key.sk)
        print "public  key:", pub.encode('hex')
        print "public  key:", py_pub.encode('hex')

        nacl = libnacl.nacl.crypto_scalarmult

        signature = key.signature(self.data)
        # print "signature:", signature.encode('hex')

        msg = "".join([chr(i) for i in range(255)])
        msg1 = msg + '0'
        msg2 = msg + '1'

        num_q = self.pow(2, 255) - 19
        print "int q:%0x" % num_q

        int_msg1 = int(msg1.encode('hex'), 16)
        int_msg2 = int(msg2.encode('hex'), 16)

        p1 = 2**52 + 27742317777372353535851937790883648493

        # num_q = num_base

        k = "4a0b1a5b4b2daf58a211cc39a5d3141ac615c62716d756e90c911673e03a7c4a".decode('hex')
        # k = "9fab25fdea70f6ffb9185fabf26f1d6c7d796e989dcaf083a900501e263c5260".decode('hex')
        int_k = int(k.encode('hex'), 16) % num_q
        #libnacl.randombytes(libnacl.crypto_scalarmult_SCALARBYTES)

        # print "int k:", int_k
        point_k = libnacl.crypto_scalarmult_base(k)

        r = int(point_k.encode('hex'), 16) % num_q
        print "int r:", r
        print "int r:", point_k.encode('hex')

        d = int(key.key.hex_sk(), 16)
        # print "int d:", d
        # print "int d:", "%0x" % d
        print "int d:", key.key.hex_sk()

        s1 = (_modinv(int_k, num_q) * ( int_msg1 + r * d )) % num_q
        # print "\nint s1 : ", s1
        s2 = (_modinv(int_k, num_q) * ( int_msg2 + r * d )) % num_q
        # print "int s2 : ", s2


        m2m1 = ( int_msg2 - int_msg1 ) % num_q
        s2s1 = ( s2 - s1 ) % num_q
        print "s2 - s1 :", s2s1
        print "m2 - m1 :", m2m1
        inv_s2s1 = _modinv(s2s1, num_q)

        recovered_k = ( m2m1 * inv_s2s1 ) % num_q
        if int_k != recovered_k:
            print "k value did not match"
            print "*" * 20
        # print "\noriginal  k:", int_k
        # print "recovered k:", recovered_k

        inv_r = _modinv(r, num_q)
        skm = (s1 * int_k - int_msg1)
        print "skm:", skm
        dd = skm  * inv_r % num_q
        if skm < 0:
            dd = dd + num_q
        if dd < p1 :
            print "dd less than p1"
        else:
            print "dd over p1"
        print "this should be correct: %0x" % dd
        recovered_d =  ((s1 * int_k - int_msg1) * inv_r ) % num_q + num_q
        recovered_d2 = ((s2 * int_k - int_msg2) * inv_r ) % num_q

        print "\n"
        dd1 = "%032x" % recovered_d
        dd2 = "%032x" % recovered_d2

        new_sk = LibNaCLSK(binarykey=dd1.decode('hex'))
        print new_sk.key.pk.encode('hex')
        new_sk2 = LibNaCLSK(binarykey=dd2.decode('hex'))
        print new_sk2.key.pk.encode('hex')
        print "\n"


        print "*" * 100
        print "actual   key:", key.key.sk.encode('hex')
        # print "recovered d1:", recovered_d
        # print "recovered d2:", recovered_d2
        print "recovered d1: %0x" % recovered_d
        print "recovered d2: %0x" % recovered_d2
        print "*" * 100

        if d == recovered_d:
            print "*" * 10, "Private key recovered successfully", "*" * 10

        # 9fab25fdea70f6ffb9185fabf26f1d6c7d796e989dcaf083a900501e263c5268
        # 1fab25fdea70f6ffb9185fabf26f1d6c7d796e989dcaf083a900501e263c527b
        # 1fab25fdea70f6ffb9185fabf26f1d6c7d796e989dcaf083a900501e263c5255
        #  fab25fdea70f6ffb9185fabf26f1d6bc1a2a5c4e3166cfa905ad430e197df13


        rec_s1 = (_modinv(inv_r, num_q) * (int_msg1 + r * recovered_d)) % num_q
        print "rec s1 : ", rec_s1
        rec_s2 = (_modinv(int_k, num_q) * (int_msg2 + r * recovered_d2)) % num_q
        print "rec s2 : ", rec_s2


        # Start testing the signature verification
        w = _modinv(s1, num_q)
        u1 = int_msg1 * w % num_q
        print "u1:", u1
        u1_bin =( "%0x" % u1 )
        print "len:", libnacl.crypto_box_SECRETKEYBYTES
        print "len:", len(u1_bin)
        u2 = r * w % num_q
        u2_bin = ("%0x" % u2)

        u1G_bin = libnacl.crypto_scalarmult_base(u1_bin)
        u1G = int(u1G_bin.encode('hex'), 16)
        print "len u1G:", len(u1G_bin)

        print "size:", libnacl.crypto_scalarmult_BYTES

        buf = ctypes.create_string_buffer(libnacl.crypto_scalarmult_BYTES)
        ret = libnacl.nacl.crypto_scalarmult(buf, u2_bin, pub)
        if ret:
            raise libnacl.CryptError('Failed to compute scalar product')
        x1 = buf.raw

        sum = curve25519.add_points(u1G_bin, x1)

        # sum = (int(x1.encode('hex'), 16) + u1G) % num_q

        print "sum:", "%s" % sum.encode('hex')
        print "r :", "%0x" % r

        self.assertTrue(self.ec.is_valid_signature(key.pub(), self.data, signature))

    def pow_mod(self, x, y, z):
        "Calculate (x ** y) % z efficiently."
        number = 1
        while y:
            if y & 1:
                number = number * x % z
            y >>= 1
            x = x * x % z
        return number

    def pow(self, x, y):
        "Calculate (x ** y) efficiently."
        number = 1
        while y:
            if y & 1:
                number = number * x
            y >>= 1
            x = x * x
        return number