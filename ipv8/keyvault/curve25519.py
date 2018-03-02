from math import sqrt

from cryptography.hazmat.primitives.asymmetric.rsa import _modinv

__all__ = ['scalarmult', 'scalarmult_base', 'calculate_y', 'add_points', 'subtract_points', 'double_point', 'x_point']

# implementation is a translation of the pseudocode
# specified in RFC7748: https://tools.ietf.org/html/rfc7748

P = 2 ** 255 - 19
A24 = 121665


def cswap(swap, x_2, x_3):
    """
    Constant time swapping resistant against side channel attacks.
    :param swap: Swap or not
    :param x_2: FieldElement 1
    :param x_3: FieldElement 2
    :return: Returns swapped tuple
    """
    dummy = swap * ((x_2 - x_3) % P)
    x_2 = x_2 - dummy
    x_2 %= P
    x_3 = x_3 + dummy
    x_3 %= P
    return (x_2, x_3)


def X25519(k, u):
    """
    Computes the scalar multiplication on the group element of the curve.
    :param k: Scalar value (integer)
    :param u: Group element (integer)
    :return: Returns the affine x-coordinate of the point after scalar multiplication.
    """
    x_1 = u
    x_2 = 1
    z_2 = 0
    x_3 = u
    z_3 = 1
    swap = 0

    for t in reversed(xrange(255)):
        k_t = (k >> t) & 1
        swap ^= k_t
        x_2, x_3 = cswap(swap, x_2, x_3)
        z_2, z_3 = cswap(swap, z_2, z_3)
        swap = k_t

        A = x_2 + z_2
        A %= P

        AA = A * A
        AA %= P

        B = x_2 - z_2
        B %= P

        BB = B * B
        BB %= P

        E = AA - BB
        E %= P

        C = x_3 + z_3
        C %= P

        D = x_3 - z_3
        D %= P

        DA = D * A
        DA %= P

        CB = C * B
        CB %= P

        x_3 = ((DA + CB) % P)**2
        x_3 %= P

        z_3 = x_1 * (((DA - CB) % P)**2) % P
        z_3 %= P

        x_2 = AA * BB
        x_2 %= P

        z_2 = E * ((AA + (A24 * E) % P) % P)
        z_2 %= P

    x_2, x_3 = cswap(swap, x_2, x_3)
    z_2, z_3 = cswap(swap, z_2, z_3)

    return (x_2 * pow(z_2, P - 2, P)) % P

# Equivalent to RFC7748 decodeUCoordinate followed by decodeLittleEndian
def unpack(s):
    if len(s) != 32:
        raise ValueError('Invalid Curve25519 scalar (len=%d)' % len(s))
    t = sum(ord(s[i]) << (8 * i) for i in range(31))
    t += ((ord(s[31]) & 0x7f) << 248)
    return t


def pack(n):
    return ''.join([chr((n >> (8 * i)) & 255) for i in range(32)])


def clamp(n):
    n &= ~7
    n &= ~(128 << 8 * 31)
    n |= 64 << 8 * 31
    return n % P


def scalarmult(n, p):
    """
    Multiplies group element p by integer n.
    :param n: Scalar value (32-byte string)
    :param p: Group element point (32-byte string)
    :return: Returns the resulting group element as 32-byte string.
    """
    n = clamp(unpack(n))
    p = unpack(p)
    return pack(X25519(n, p))

def scalarmult_unclamped(n, p):
    """
    Multiplies group element p by integer n.
    :param n: Scalar value (32-byte string)
    :param p: Group element point (32-byte string)
    :return: Returns the resulting group element as 32-byte string.
    """
    n = unpack(n)
    p = unpack(p)
    return pack(X25519(n, p))

def scalarmult_base(n):
    """
    Computes scalar product of standard group element (9) and n.
    :param n: Scalar value (32-byte string)
    :return: Returns the resulting group element as 32-byte string.
    """
    n = clamp(unpack(n))
    return pack(X25519(n, 9))

def scalarmult_base_unclamped(n):
    """
    Computes scalar product of standard group element (9) and n.
    :param n: Scalar value (32-byte string)
    :return: Returns the resulting group element as 32-byte string.
    """
    n = unpack(n)
    return pack(X25519(n, 9))


def calculate_y(x):
    """
    Computes affine y coordinates on the curve for given x.
    :param x: Given x coordinate (integer)
    :return: [y1, p-y1] two possible y coordinates
    """
    A = 486662
    A = (A + x) % P
    A = (A * x) % P
    A = (A * x) % P
    A = (A + x) % P
    y_coords = _prime_mod_sqrt(A, P)
    return y_coords[0] if y_coords[0] < y_coords[1] else y_coords[1]


def subtract_points(p1, p2):
    """
    Subtract two points (p1 - p2)
    :param p1: ECPoint 1 (32-byte string)
    :param p2: ECPoint 2 (32-byte string)
    :return: Returns 32-byte string: p1 + p2
    """
    p1 = unpack(p1)
    p2 = unpack(p2)
    return pack(montgomery_point_subtraction(p1, p2))


def add_points(p1, p2):
    """
    Adds two points (p1 + p2)
    :param p1: ECPoint 1 (32-byte string)
    :param p2: ECPoint 2 (32-byte string)
    :return: Returns 32-byte string: p1 + p2
    """
    p1 = unpack(p1)
    p2 = unpack(p2)
    if p1 == p2:
        return pack(montgomery_point_doubling(p1))
    return pack(montgomery_point_addition(p1, p2))


def double_point(p1):
    """
    Doubles the point (2 * p1)
    :param p1: ECPoint 1 (32-byte string)
    :return: Returns 32-byte string: 2 * p1
    """
    p1 = unpack(p1)
    return pack(montgomery_point_doubling(p1))


def montgomery_point_subtraction(x1, x2):
    """
    Computes Montgomery point subtraction for two points P1, P2
    :param x1: Affine x-coordinate of first point P1 (integer)
    :param x2: Affine x-coordinate of second point P1 (integer)
    :return: Returns affine x-coordinate of P3 = P1 + P2 as integer
    """
    y1 = calculate_y(x1)
    y2 = calculate_y(x2)

    numer = pow(x2 * y1 - x1 * y2, 2, P)
    denom = x1 * x2 * pow(x2 - x1, 2, P)
    x3 = (_modinv(denom, P) * numer) % P
    return x3


def montgomery_point_addition(x1, x2):
    """
    Computes Montgomery point addition for two points P1, P2
    :param x1: Affine x-coordinate of first point P1 (integer)
    :param x2: Affine x-coordinate of second point P2 (integer)
    :return: Returns affine x-coordinate of P3 = P1 + P2 as integer
    """
    y1 = calculate_y(x1)
    y2 = -1 * calculate_y(x2)

    numer = pow(x2 * y1 - x1 * y2, 2, P)
    denom = (x1 * x2 * pow(x2 - x1, 2, P)) % P
    x3 = (_modinv(denom, P) * numer) % P
    return x3


def montgomery_point_doubling(x1):
    """
    Computes Montgomery point doubling for the given point P1.
    :param x1: Affine x-coordinate of the point P1 (integer)
    :return: Returns affine x-coordinate of P2 = 2 * P1 as integer
    """
    return (pow(x1 * x1 - 1, 2, P) * _modinv((4 * x1 * (x1 * x1 + 486662 * x1 + 1)), P)) % P


def x_point(x_int, p1):
    """
    Computes the scalar multiplication on the given point.
    :param x_int: Scalar value (integer)
    :param p1: ECPoint P1 (32-byte string)
    :return: Returns the point after scalar multiplication
    """
    p = unpack(p1)
    return pack(X25519(x_int, p))


def _legendre_symbol(a, p):
    """
    Legendre symbol
    Define if a is a quadratic residue modulo odd prime
    http://en.wikipedia.org/wiki/Legendre_symbol
    """
    ls = pow(a, (p - 1)/2, p)
    if ls == p - 1:
        return -1
    return ls


def _prime_mod_sqrt(a, p):
    """
    Square root modulo prime number
    Solve the equation
        x^2 = a mod p
    and return list of x solution
    http://en.wikipedia.org/wiki/Tonelli-Shanks_algorithm
    """
    a %= p

    # Simple case
    if a == 0:
        return [0]
    if p == 2:
        return [a]

    # Check solution existence on odd prime
    if _legendre_symbol(a, p) != 1:
        return []

    # Simple case
    if p % 4 == 3:
        x = pow(a, (p + 1)/4, p)
        return [x, p-x]

    # Factor p-1 on the form q * 2^s (with Q odd)
    q, s = p - 1, 0
    while q % 2 == 0:
        s += 1
        q //= 2

    # Select a z which is a quadratic non resudue modulo p
    z = 1
    while _legendre_symbol(z, p) != -1:
        z += 1
    c = pow(z, q, p)

    # Search for a solution
    x = pow(a, (q + 1)/2, p)
    t = pow(a, q, p)
    m = s
    while t != 1:
        # Find the lowest i such that t^(2^i) = 1
        i, e = 0, 2
        for i in xrange(1, m):
            if pow(t, e, p) == 1:
                break
            e *= 2

        # Update next value to iterate
        b = pow(c, 2**(m - i - 1), p)
        x = (x * b) % p
        t = (t * b * b) % p
        c = (b * b) % p
        m = i

    return [x, p-x]


def custom_signature(sk, msg, common_base):
    """
    Custom signature for Curve25519
    :param msg:
    :param common_base:
    :return:
    """
    d = unpack(sk)
    z_unpacked = unpack(msg)
    k_unpacked = unpack(common_base)

    point_k = scalarmult_base(common_base)

    r = unpack(point_k)
    s = (_modinv(k_unpacked, P) * (z_unpacked + r * d)) % P
    inv_s = _modinv(s, P)
    # print "inv s:", pack(inv_s).encode('hex')

    w = _modinv(s, P)
    print "inv s:", pack(w).encode('hex')
    u1 = z_unpacked * w % P
    u2 = r * w % P
    u3 = r * w * d % P
    print "r:", point_k.encode('hex')
    print "u2:", u2

    pk = scalarmult_base(sk)
    print "pk:", pk.encode('hex')
    u1_point = scalarmult_base(pack(u1))
    u2_point = scalarmult_unclamped(pack(u2), pk)
    u3_point = scalarmult_base(pack(u3))

    print "u1 point:", u1_point.encode('hex')
    print "u2 point:", u2_point.encode('hex')
    print "u3 point:", u3_point.encode('hex')

    sum = add_points(u1_point, u2_point)
    print "sum:", sum.encode('hex')

    return "%s%s" % (point_k, pack(s))


def double_signature(sk, msg, common_base):
    """
    Custom signature for Curve25519
    :param msg:
    :param common_base:
    :return:
    """
    d = unpack(sk)
    z_unpacked = unpack(msg)
    k_unpacked = unpack(common_base)

    point_k = scalarmult_base(common_base)

    r = clamp(unpack(point_k))
    s = (_modinv(k_unpacked, P) * (z_unpacked + r * d)) % P
    inv_s = _modinv(s, P)
    # print "inv s:", pack(inv_s).encode('hex')

    w = _modinv(s, P)
    print "inv s:", pack(w).encode('hex')
    u1 = z_unpacked * w % P
    u2 = r * w % P
    u3 = r * w * d % P
    print "r:", point_k.encode('hex')
    print "u2:", u2

    pk = scalarmult_base(sk)
    print "pk:", pk.encode('hex')
    u1_point = scalarmult_base(pack(u1))
    u2_point = scalarmult_unclamped(pack(u2), pk)
    u3_point = scalarmult_base(pack(u3))

    print "u1 point:", u1_point.encode('hex')
    print "u2 point:", u2_point.encode('hex')
    print "u3 point:", u3_point.encode('hex')

    sum = add_points(u1_point, u2_point)
    print "sum:", sum.encode('hex')

    return "%s%s" % (pack(r), pack(s))


def verify_custom_signature(pk, msg, signature, common_base):
    """
    Verify custom signature for Curve25519
    :param pk:
    :param msg:
    :param common_base:
    :return:
    """
    print "pk:", pk.encode('hex')
    z_unpacked = unpack(msg)

    r_packed = signature[:32]
    s_packed = signature[32:]

    r = unpack(r_packed)
    s = unpack(s_packed)

    w = _modinv(s, P)
    print "inv s:", pack(w).encode('hex')
    u1 = z_unpacked * w % P
    u2 = r * w % P
    print "r:", r
    print "u2:", u2

    u1_point = scalarmult_base(pack(u1))
    u2_point = scalarmult(pack(u2), pk)

    print "u1 point:", u1_point.encode('hex')
    print "u2 point:", u2_point.encode('hex')

    sum = add_points(u1_point, u2_point)
    print "sum:", sum.encode('hex')

    r1 = add_points(u1_point, u2_point)
    r1 = add_points(u2_point, u1_point)
    r2 = subtract_points(u1_point, u2_point)
    print "r1: ", r1.encode('hex')
    print "r2: ", r2.encode('hex')
    print "r : ", r_packed.encode('hex')


