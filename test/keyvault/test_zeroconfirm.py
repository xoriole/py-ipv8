import unittest

import libnacl
from ipv8.keyvault.crypto import ECCrypto
from cryptography.hazmat.primitives.asymmetric.rsa import _modinv
# import cryptography.hazmat.backends.openssl.ec._EllipticCurvePublicKey
from ipv8.keyvault.private.libnaclkey import LibNaCLSK


class TestZeroConfirmation(unittest.TestCase):
    """
    Test whether signatures can be created and then decoded correctly.
    """

    def setUp(self):
        self.ec = ECCrypto()
        self.data = "".join([chr(i) for i in range(256)])

    def test_sec_curve(self):
        test_key_bin = "30530201010415035fe72ea11f3e61984b8fa9c493b451b7a030a29fa00706052b81040001a12e032c000" \
                       "400e09b92268f8742631ea9e786285f41d332775dba02f9c31d24782fdc7a214d5951d80f29580cce3ebf"
        key = self.ec.key_from_private_bin(test_key_bin.decode('hex'))
        print "public key:", type(key.hex_pk())
        # print "key to bin:", key.key_to_bin().encode('hex')


        signature = key.signature(self.data)

        print "signature: %s, type:%s" % (signature.encode('hex'), type(signature))
        print "signature: %s, type:%s" % (signature, type(signature))


    def test_curve25519(self):
        """
        Check if curve25519 keys can be recovered from two signatures with same k value
        """
        test_key_bin = "4c69624e61434c534b3a9fab25fdea70f6ffb9185fabf26f1d6c7d796e989" \
                       "dcaf083a900501e263c526898bbd08da7895dae4b72d0d216c8a0fcfcea34" \
                       "98c0871e651ac13562db445098"
        key_bin = test_key_bin.decode('hex')
        key = self.ec.generate_key(u"curve25519")
        # key = self.ec.key_from_private_bin(test_key_bin.decode('hex'))
        # print "private key:", key.key.hex_sk()
        # print "public  key:", key.key.hex_pk()

        pub = libnacl.crypto_scalarmult_base(key.key.sk)
        print "public  key:", pub.encode('hex')

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
        # print "int r:", r

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
        dd1 = "%0x" % recovered_d
        dd2 = "%0x" % recovered_d2

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