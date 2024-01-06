from random import randbytes
from secrets import randbelow
from unittest import TestCase

from ecc import N, G, S256Point, PrivateKey, SchnorrSignature
from helper import (
    big_endian_to_int,
    encode_varint,
    int_to_big_endian,
)
from hash import hash_challenge, tagged_hash
from musig import NoncePrivateShare, NoncePublicShare, NonceAggregator


def hash_frostgenerate(msg):
    return tagged_hash(b"FROST/generate", msg)


def hash_frostnoncecoef(msg):
    return tagged_hash(b"FROST/noncecoef", msg)


def lagrange(participants, x_i, x):
    # start the value at 1
    # loop through the participants
        # if the participant is not x_1
            # multiply value by (x-x_j)/(x_i-x_j) using field division
    # return the value mod N
    raise NotImplementedError


def lagrange_coef(participants, x_i):
    # return the lagrange value where x=0
    raise NotImplementedError


def recover_secret(values):
    # return the sum of the values mod by N
    return sum(values) % N


class LaGrangeTest(TestCase):
    def test_lagrange(self):
        participants = [1, 3, 5, 6]
        y_values = [1913, 1971, 2009, 2024]
        lagrange_values = [lagrange_coef(participants, x_i) for x_i in participants]
        secret = recover_secret(
            [c_i * y_i for c_i, y_i in zip(lagrange_values, y_values)]
        )
        self.assertEqual(secret, 0x751)


class PrivatePolynomial:
    """Polynomial with scalar coefficients. Private key is at f(0)"""
    def __init__(self, coefficients):
        self.coefficients = coefficients
        self.t = len(coefficients)
        # the constant term is the "private key" for this polynomial
        self.private_key = PrivateKey(coefficients[0])
        # we compute the corresponding PublicPolynomial which have ECC points
        # as coefficients
        points = [s * G for s in self.coefficients]
        self.public = PublicPolynomial(points)

    def y_value(self, x):
        """return the y value y = f(x) where f is the private polynomial"""
        # start y at 0
        # compute y = a_0 + a_1 * x + a_2 * x^2 + ... + a_(t-1) * x^(t-1)
        # return y % N
        raise NotImplementedError

    @classmethod
    def generate(cls, t):
        coefs = [randbelow(N) for _ in range(t)]
        return cls(coefs)


class PrivatePolynomialTest(TestCase):
    def test_y_value(self):
        coefs = [21000000, 11111111, 2222222, 3333333]
        pp = PrivatePolynomial(coefs)
        self.assertEqual(pp.y_value(7), 1350999874)


class PublicPolynomial:
    """Polynomial with ECC Point coefficients. We can combine many of these
    to create a public key for the shared secret from Shamir."""
    def __init__(self, points):
        self.points = points
        # the number of coefficients also corresponds to the threshold
        self.t = len(points)
        # the constant term of the polynomial is the public key
        self.public_key = points[0]

    def __repr__(self):
        return "\n".join([p.__repr__() for p in self.points])

    def y_value(self, x):
        """return the y value y = f(x) where f is the public polynomial"""
        terms = []
        # compute y = A_0 + A_1 * x + A_2 * x^2 + ... + A_(t-1) * x^(t-1)
        for coef_index, point in enumerate(self.points):
            terms.append(pow(x, coef_index, N) * self.points[coef_index])
        # return the sum
        return S256Point.sum(terms)


class Dealer:
    def __init__(self, coefs):
        self.private_polynomial = PrivatePolynomial(coefs)
        self.t = len(coefs)
        self.public_polynomial = self.private_polynomial.public
        self.group_point = self.public_polynomial.y_value(0)

    @classmethod
    def generate(cls, t, rand=None):
        if rand is None:
            rand = randbytes(32)
        coefs = [
            big_endian_to_int(
                hash_frostgenerate(rand + encode_varint(t) + encode_varint(i))
            )
            for i in range(t)
        ]
        return cls(coefs)

    def y_value(self, x):
        return self.private_polynomial.y_value(x)

    def create_signer(self, x):
        # get the y value
        # return the FrostSigner with x, y and the public polynomial
        raise NotImplementedError


class DealerTest(TestCase):
    def test_create_signer(self):
        dealer = Dealer.generate(4)
        signer = dealer.create_signer(1)
        self.assertEqual(signer.t, 4)


class SigningContext:
    """Represents the data needed for a participant to sign a message"""
    def __init__(self, participants, nonceagg, msg, group_polynomial, merkle_root=None):
        self.participants = participants
        # the group nonce we are using
        self.nonceagg = nonceagg
        # the message we are signing (z)
        self.msg = msg
        self.group_polynomial = group_polynomial
        self.merkle_root = merkle_root
        if merkle_root is None:
            self.group_point = group_polynomial.y_value(0)
        else:
            self.group_point = group_polynomial.y_value(0).tweaked_key(merkle_root)
        preimage = self.nonceagg.serialize() + self.group_point.xonly() + self.msg
        self.nonce_coef = big_endian_to_int(hash_frostnoncecoef(preimage)) % N
        # make the nonce point available
        self.nonce_point = nonceagg.nonce_point(self.nonce_coef)

    def address(self, network="mainnet"):
        return self.group_polynomial.y_value(0).p2tr_address(self.merkle_root, network)

    def challenge(self):
        """The message being signed by each participant so it aggregates to
        a single signature. This is what will get verified in the end
        d = H(R || P || z)"""
        preimage = self.nonce_point.xonly() + self.group_point.xonly() + self.msg
        return big_endian_to_int(hash_challenge(preimage))

    def verify(self, partial_sig, nonce_public_share, x_i):
        """Verify that the partial signature is valid for a particular nonce
        # get the nonce point for this particular pubkey
        # we negate if it's odd
        # negate the participant point if our group point is odd
        # c_i is our lagrange coefficient for this x_i
        # d is our challenge H(R||P||z)
        # return whether s_i * G = R_i + c_i * d * P_i
        raise NotImplementedError


class FrostSigner:
    """Represents one of n signers in a t-of-n FROST"""
    def __init__(self, x, y, public_polynomial):
        self.x = x  # this participant's x coordinate
        self.private_key = PrivateKey(y)  # this participant's secret, or y coordinate
        self.group_polynomial = (
            public_polynomial  # the public polynomial from the dealer
        )
        self.group_point = public_polynomial.y_value(0)  # F(x)=P
        self.t = public_polynomial.t
        self.point = self.private_key.point
        if self.point != self.group_polynomial.y_value(self.x):
            raise ValueError("secret does not correspond with the public polynomial")
        self.private_nonce_share = None

    def generate_nonce_share(self, msg=None, extra=None, rand=None):
        # If we don't have a nonce yet, generate it using the secure generation algo
        self.private_nonce_share = NoncePrivateShare.generate_nonce_share(
            self.point, self.private_key, self.group_point, msg, extra, rand
        )
        return self.private_nonce_share.public_share

    def nonce(self, coef):
        """k_i = l_i + b * m_i"""
        if self.private_nonce_share is None:
            raise RuntimeError("Nonce shares have not been defined yet")
        return self.private_nonce_share.nonce(coef)

    def sign(self, context):
        """Sign the message in the context using the nonces in the context"""
        # if the group nonce point is odd, we need to negate the k_i
        # use the nonce method with the context's nonce_coef
        # get this point's lagrange coefficient
        # get the challenge (d = H (R || P || z)
        # if the group point is odd, we need to negate the secret (e_i)
        # s_i = k + c_i * d * e_i, where d is the challenge
        # the partial signature is s as big endian, 32 bytes
        # check that partial sig verifies using the verify method of context
        # return the partial signature
        raise NotImplementedError


class FrostCoordinator:
    def __init__(self, participants, public_polynomial, merkle_root=None):
        self.participants = participants
        self.group_polynomial = public_polynomial
        self.merkle_root = merkle_root
        if merkle_root is None:
            self.tweak_amount = 0
            self.group_point = public_polynomial.y_value(0)
        else:
            self.tweak_amount = big_endian_to_int(
                public_polynomial.y_value(0).tweak(merkle_root)
            )
            self.group_point = public_polynomial.y_value(0).tweaked_key(merkle_root)
        self.secs = [self.group_polynomial.y_value(x).sec() for x in self.participants]
        self.nonce_shares = {}
        self.partial_sigs = {}
        self.signing_context = None
        self.nonceagg = None

    def create_signing_context(self, msg):
        """Create the data needed by each participant to sign"""
        self.aggregate_nonce_shares()
        self.signing_context = SigningContext(
            self.participants,
            self.nonceagg,
            msg,
            self.group_polynomial,
            self.merkle_root,
        )
        return self.signing_context

    def clear_nonces(self):
        self.nonce_shares = {}

    def register_nonce_share(self, x, nonce_public_share):
        self.nonce_shares[x] = nonce_public_share

    def aggregate_nonce_shares(self):
        """Compute the nonce aggregator (S and T)"""
        if self.nonceagg is None:
            for x in self.participants:
                if not self.nonce_shares.get(x):
                    raise RuntimeError("Not everyone has registered a nonce")
            self.nonceagg = NonceAggregator.from_nonce_shares(
                self.nonce_shares.values()
            )
        return self.nonceagg

    def register_partial_sig(self, x_i, partial_sig):
        """Register the signature share for a particular pubkey"""
        # make sure the partial signature is not too big
        s = big_endian_to_int(partial_sig)
        if s >= N:
            raise ValueError("Partial Sig is too big")
        # make sure the partial sig verifies
        nonce_share = self.nonce_shares[x_i]
        if not self.signing_context.verify(partial_sig, nonce_share, x_i):
            raise ValueError("Partial Signature does not Validate")
        self.partial_sigs[x_i] = s

    def compute_sig(self):
        """Aggregates the partial signatures"""
        # check if every participant has registered a partial signature
        # sum up the partial signatures to a complete s
        # account for the tweak by checking tweak_amount
            # challenge d = H(R||Q||m)  is in the signing context
            # s = s + d * t if group point is even, s = s - d * t if odd
        # get the group nonce point (R) from the signing context
        # create the signature
        # sanity check that the generated signature validates
        # return the signature
        raise NotImplementedError


class PartialSigTest(TestCase):
    def test_verify(self):
        dealer = Dealer([12345, 67890])
        msg = b"Hello World!"
        participants = [1, 2]
        coor = FrostCoordinator(participants, dealer.public_polynomial)
        raw_nonce_1 = bytes.fromhex(
            "03ed214e8ce499d92a2085e7e6041b4f081c7d29d8770057fc705a131d2918fcdb02609ae8d31e3b290e74483776c1c8dfc2756b87d9635d654eb9e1ca95c228b169"
        )
        nonce_share_1 = NoncePublicShare.parse(raw_nonce_1)
        raw_nonce_2 = bytes.fromhex(
            "02ffe558e388852f0120e46af2d1b370f85854a8eb0841811ece0e3e03d282d57c02d42d696f2c343dc67d80fcd85dbbdb2edef3cac71126625d0cbcacc231a00015"
        )
        nonce_share_2 = NoncePublicShare.parse(raw_nonce_2)
        coor.register_nonce_share(1, nonce_share_1)
        coor.register_nonce_share(2, nonce_share_2)
        context = coor.create_signing_context(msg)
        sig_1 = bytes.fromhex(
            "a9752dd83e4714576d301274b89ba1042df1c666c4db491b9ba8fb70aaaadc1f"
        )
        sig_2 = bytes.fromhex(
            "82f5ea3360c82882a851abf95324d079392fd0c70d7e56a15e0aa8e5c3fb983f"
        )
        self.assertTrue(context.verify(sig_1, nonce_share_1, 1))
        self.assertTrue(context.verify(sig_2, nonce_share_2, 2))

    def test_sign(self):
        dealer = Dealer.generate(4)
        msg = b"Hello World!"
        signers = {x: dealer.create_signer(x) for x in range(1, 8)}
        participants = [1, 2, 5, 7]
        coor = FrostCoordinator(participants, dealer.public_polynomial)
        for x in participants:
            p = signers[x]
            nonce_share = p.generate_nonce_share(msg=msg, rand=b"")
            coor.register_nonce_share(x, nonce_share)
        context = coor.create_signing_context(msg)
        for x in participants:
            p = signers[x]
            partial_sig = p.sign(context)
            coor.register_partial_sig(x, partial_sig)
            self.assertTrue(context.verify(partial_sig, coor.nonce_shares[x], x))

    def test_compute_sig(self):
        msg = bytes.fromhex(
            "e8a9399c64a4a2b6c190eaf1111568a91ae1db590696aa5adfc875205aaefffe"
        )
        dealer = Dealer([21000000, 1234567890])
        signers = {x: dealer.create_signer(x) for x in range(1, 4)}
        merkle_root = b""
        participants = [1, 3]
        coor = FrostCoordinator(
            participants, dealer.public_polynomial, merkle_root=merkle_root
        )
        for x in participants:
            p = signers[x]
            nonce_share = p.generate_nonce_share(msg=msg, rand=b"")
            coor.register_nonce_share(x, nonce_share)
        context = coor.create_signing_context(msg)
        partial_sig_1 = bytes.fromhex(
            "0aebd63a6cd3863a2a104a03ccfb88f958274050380a9e230f288c18fc834177"
        )
        partial_sig_3 = bytes.fromhex(
            "6a8ef5084dcaa656f7ef5ed52867f12a9420425703500dc7d09c3bd3a3d22933"
        )
        self.assertEqual(signers[1].sign(context), partial_sig_1)
        self.assertEqual(signers[3].sign(context), partial_sig_3)
        coor.register_partial_sig(1, partial_sig_1)
        coor.register_partial_sig(3, partial_sig_3)
        sig = coor.compute_sig()
        self.assertTrue(coor.group_point.verify_schnorr(msg, sig))
