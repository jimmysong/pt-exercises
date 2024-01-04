from random import randbytes
from unittest import TestCase

from ecc import G, N, S256Point, PrivateKey, SchnorrSignature
from hash import (
    hash_challenge,
    hash_keyagglist,
    hash_keyaggcoef,
    hash_musigaux,
    hash_musignonce,
    hash_musignoncecoef,
)
from helper import big_endian_to_int, int_to_big_endian, xor_bytes


class NonceAggregator:
    """Represents the nonces submitted"""
    def __init__(self, s, t):
        self.s = s
        self.t = t

    def serialize(self):
        return self.s.sec() + self.t.sec()

    def nonce_point(self, coef):
        # R = S + bT
        return self.s + coef * self.t

    @classmethod
    def from_nonce_shares(cls, nonce_shares):
        s = S256Point.sum([share.s for share in nonce_shares])
        t = S256Point.sum([share.t for share in nonce_shares])
        return cls(s, t)

    @classmethod
    def parse(cls, raw):
        s = S256Point.parse(raw[:33])
        t = S256Point.parse(raw[33:])
        return cls(s, t)


class NoncePrivateShare:
    """Represents the k's that are used in signing"""
    def __init__(self, l, m, pubkey):
        if l <= 0 or l >= N or m <= 0 or m >= N:
            raise ValueError("nonce is out of range")
        self.l = l
        self.m = m
        self.pubkey = pubkey
        self.public_share = NoncePublicShare(l * G, m * G)

    def nonce(self, coef):
        # k_i = l_i + b * m_i
        return (self.l + coef * self.m) % N

    @classmethod
    def parse(cls, b):
        l = big_endian_to_int(b[:32])
        m = big_endian_to_int(b[32:64])
        pubkey = S256Point.parse(b[64:])
        return cls(l, m, pubkey)

    @classmethod
    def generate_nonce_share(
        cls, pubkey, priv=None, aggregate_pubkey=None, msg=None, extra=None, rand=None
    ):
        """Nonce generation algorithm per BIP327"""
        if rand is None:
            rand = randbytes(32)
        if priv:
            rand = xor_bytes(int_to_big_endian(priv.secret, 32), hash_musigaux(rand))
        preimage = rand + b"\x21" + pubkey.sec()
        if aggregate_pubkey is None:
            agg = b""
        else:
            agg = aggregate_pubkey.xonly()
        preimage += bytes([len(agg)]) + agg
        if msg is None:
            msg_prefixed = b"\x00"
        else:
            msg_prefixed = b"\x01" + int_to_big_endian(len(msg), 8) + msg
        preimage += msg_prefixed
        if extra is None:
            extra = b""
        preimage += int_to_big_endian(len(extra), 4) + extra
        l = big_endian_to_int(hash_musignonce(preimage + b"\x00")) % N
        m = big_endian_to_int(hash_musignonce(preimage + b"\x01")) % N
        return cls(l, m, pubkey)


class NoncePublicShare:
    """Represents the participant r's that are summed for group nonce creation"""
    def __init__(self, s, t):
        self.s = s
        self.t = t

    def nonce_point(self, coef):
        # R_i = S-i + b T_i
        return self.s + coef * self.t

    def serialize(self):
        return self.s.sec() + self.t.sec()

    @classmethod
    def parse(cls, b):
        s = S256Point.parse(b[:33])
        t = S256Point.parse(b[33:])
        return cls(s, t)


class KeyAggregator:
    """Structure for aggregating keys to a group point for MuSig2"""
    def __init__(self, points, merkle_root=None):
        # the points that make up the MuSig2 aggregate key
        self.points = points
        # compute the group commitment (L)
        self.group_commitment = self.compute_group_commitment()
        # The group point (P)
        self.group_point = self.compute_group_point()
        # any tweaking we need to do to the group point
        if merkle_root is None:
            self.tweak_amount = 0
        else:
            self.tweak_amount = big_endian_to_int(self.group_point.tweak(merkle_root))
            self.group_point = self.group_point.tweaked_key(merkle_root)

    def compute_group_commitment(self):
        """L = H(P_1 || P_2 || ... || P_n)"""
        # start with the preimage being an empty byte-string
        preimage = b""
        # loop through the points
        for point in self.points:
            # concatenate the compressed sec of each point to the preimage
            preimage += point.sec()
        # return the hash_keyagglist of the preimage
        return hash_keyagglist(preimage)

    def compute_group_point(self):
        """P = c_1 * P_1 + c_2 * P_2 + ... + c_n * P_n"""
        # create a list of terms for collecting the sum
        terms = []
        # loop through the points
        for p in self.points:
            # compute the coefficient using keyagg_coef
            c = self.keyagg_coef(p)
            # append the coef times the point to the terms
            terms.append(c * p)
        # return the sum of the terms using S256Point.sum
        return S256Point.sum(terms)

    def keyagg_coef(self, point):
        """the coefficient for each pubkey, based on the group commitment and
        the individual pubkey, except for the second point, which is 1
        c_i = H(L || P_i) except c_2 = 1"""
        # if the point is not in the list of points, raise a ValueError
        if point not in self.points:
            raise ValueError(f"{point.sec().hex()} is not a participant")
        # the second point has a coefficient of 1, everything else uses H(L||P)
        second_point = None
        for p in self.points:
            if p != self.points[0]:
                second_point = p
                break
        # if the point is the same as the second_point, return 1
        if point == second_point:
            return 1
        # coefficient is H(L || P) converted from big endian to an integer
        # where H is hash_keyaggcoef, L is the group commitment, and P is
        # the compressed sec serialization of the point
        return big_endian_to_int(hash_keyaggcoef(self.group_commitment + point.sec()))


class KeyAggTest(TestCase):
    def test_compute_group_commitment(self):
        raw_pubkeys = [
            "034a5169f673aa632f538aaa128b6348536db2b637fd89073d49b6a23879cdb3ad",
            "0225fa6a4190ddc87d9f9dd986726cafb901e15c21aafd2ed729efed1200c73de8",
            "03ed214e8ce499d92a2085e7e6041b4f081c7d29d8770057fc705a131d2918fcdb",
            "02609ae8d31e3b290e74483776c1c8dfc2756b87d9635d654eb9e1ca95c228b169",
            "02ffe558e388852f0120e46af2d1b370f85854a8eb0841811ece0e3e03d282d57c",
            "02d42d696f2c343dc67d80fcd85dbbdb2edef3cac71126625d0cbcacc231a00015",
        ]
        points = [S256Point.parse(bytes.fromhex(r)) for r in raw_pubkeys]
        keyagg = KeyAggregator(points)
        self.assertEqual(
            keyagg.group_commitment.hex(),
            "9a02b1f7c524456922ec47b4db33810e244866f68a5d4478fc5b83c43231dad0",
        )

    def test_compute_group_point(self):
        raw_pubkeys = [
            "034a5169f673aa632f538aaa128b6348536db2b637fd89073d49b6a23879cdb3ad",
            "0225fa6a4190ddc87d9f9dd986726cafb901e15c21aafd2ed729efed1200c73de8",
            "03ed214e8ce499d92a2085e7e6041b4f081c7d29d8770057fc705a131d2918fcdb",
            "02609ae8d31e3b290e74483776c1c8dfc2756b87d9635d654eb9e1ca95c228b169",
            "02ffe558e388852f0120e46af2d1b370f85854a8eb0841811ece0e3e03d282d57c",
            "02d42d696f2c343dc67d80fcd85dbbdb2edef3cac71126625d0cbcacc231a00015",
        ]
        points = [S256Point.parse(bytes.fromhex(r)) for r in raw_pubkeys]
        keyagg = KeyAggregator(points)
        self.assertEqual(
            keyagg.group_point.sec().hex(),
            "03628b3911ec6818290dbc40e0039652ceac6bef4355c6b461af870d0aafa123a0",
        )


class SigningContext:
    """Represents the data needed for a participant to sign a message"""
    def __init__(self, keyagg, nonceagg, msg):
        # keyagg will make the group point
        self.keyagg = keyagg
        # the group nonce we are using
        self.nonceagg = nonceagg
        # the message we are signing (z)
        self.msg = msg
        # make the group point available for convenience
        self.group_point = self.keyagg.group_point
        # make the nonce point available for convenience
        self.nonce_point = self.group_nonce_point()

    def keyagg_coef(self, point):
        """Convenience method"""
        return self.keyagg.keyagg_coef(point)

    def nonce_coef(self):
        """the coefficient in front of the second nonce determined by the msg"""
        preimage = self.nonceagg.serialize() + self.group_point.xonly() + self.msg
        return big_endian_to_int(hash_musignoncecoef(preimage))

    def group_nonce_point(self):
        """R = S + bT where b is the nonce coefficient, dependent on msg"""
        return self.nonceagg.nonce_point(self.nonce_coef())

    def challenge(self):
        """The message being signed by each participant so it aggregates to
        a single signature. This is what will get verified in the end
        d = H(R || P || z)"""
        preimage = (
            self.group_nonce_point().xonly() + self.group_point.xonly() + self.msg
        )
        return big_endian_to_int(hash_challenge(preimage))

    def verify(self, partial_sig, nonce_public_share, point):
        """Verify that the partial signature is valid for a particular nonce
        for a particular pubkey"""
        # get the nonce point for this particular pubkey
        # we negate if it's odd
        if self.nonce_point.even:
            r = nonce_public_share.nonce_point(self.nonce_coef())
        else:
            r = -1 * nonce_public_share.nonce_point(self.nonce_coef())
        # negate the participant point if our group point is odd
        if self.group_point.even:
            p = point
        else:
            p = -1 * point
        # c is our keyagg coefficient for this particular participant point
        c = self.keyagg_coef(point)
        # d is our challenge H(R||P||z)
        d = self.challenge()
        # return whether s_i * G = R + c_i * d * P_i
        s = big_endian_to_int(partial_sig)
        return s * G == r + c * d * p


class MuSigParticipant:
    """Represents a MuSig2 signer"""
    def __init__(self, private_key, private_share=None):
        # The private key (e_i)
        self.private_key = private_key
        # The public key/point (P_i = e_i * G)
        self.point = private_key.point
        # The nonce private share l,m which can be used to generate the nonce k
        self.private_share = private_share
        # Make sure the nonce private share belongs to this participant
        if private_share and self.point != self.private_share.pubkey:
            raise ValueError("Nonce does not correspond to the participant")

    def generate_nonce_share(
        self, aggregate_pubkey=None, msg=None, extra=None, rand=None
    ):
        # If we don't have a nonce yet, generate it using the secure generation algo
        self.private_share = NoncePrivateShare.generate_nonce_share(
            self.point, self.private_key, aggregate_pubkey, msg, extra, rand
        )
        return self.private_share.public_share

    def nonce(self, coef):
        """k_i = l_i + b * m_i"""
        if self.private_share is None:
            raise RuntimeError("Nonce shares have not been defined yet")
        return self.private_share.nonce(coef)

    def sign(self, context):
        """Sign the message in the context using the nonces in the context"""
        # if the group nonce point is odd, we need to negate the k_i
        # use the nonce method with the context's nonce_coef
        if context.nonce_point.even:
            k = self.nonce(context.nonce_coef())
        else:
            k = N - self.nonce(context.nonce_coef())
        # get this point's keyagg coefficient (c_i = H(L || P_i))
        c = context.keyagg_coef(self.point)
        # get the challenge (d = H (R || P || z)
        d = context.challenge()
        # if the group point is odd, we need to negate the secret (e_i)
        if context.group_point.even:
            e = self.private_key.secret
        else:
            e = N - self.private_key.secret
        # s_i = k + c_i * d * e_i, where d is the challenge
        s = (k + c * d * e) % N
        # the partial signature is s as big endian, 32 bytes
        partial_sig = int_to_big_endian(s, 32)
        # check that partial sig verifies using the verify method of context
        if not context.verify(partial_sig, self.private_share.public_share, self.point):
            raise RuntimeError("failed to verify")
        # return the partial signature
        return partial_sig


class PartialSigTest(TestCase):
    def test_sign(self):
        participant_1 = MuSigParticipant(PrivateKey(1000))
        participant_2 = MuSigParticipant(PrivateKey(2000))
        msg = b"Hello World!"
        nonce_share_1 = NoncePrivateShare(3000, 4000, participant_1.point)
        nonce_share_2 = NoncePrivateShare(5000, 6000, participant_2.point)
        participant_1.private_share = nonce_share_1
        participant_2.private_share = nonce_share_2
        pubkeys = [participant_1.point, participant_2.point]
        coor = MuSigCoordinator(pubkeys)
        coor.register_nonce_share(participant_1.point.sec(), nonce_share_1.public_share)
        coor.register_nonce_share(participant_2.point.sec(), nonce_share_2.public_share)
        context = coor.create_signing_context(msg)
        partial_sig = participant_1.sign(context)
        self.assertEqual(
            partial_sig.hex(),
            "1aad95d9490e4b8599377ff6a546a1d075fb4242c749dbcbc010589e23c21776",
        )

    def test_verify(self):
        participant_1 = MuSigParticipant(PrivateKey(1000))
        participant_2 = MuSigParticipant(PrivateKey(2000))
        msg = b"Hello World!"
        nonce_share_1 = NoncePrivateShare(3000, 4000, participant_1.point)
        nonce_share_2 = NoncePrivateShare(5000, 6000, participant_2.point)
        participant_1.private_share = nonce_share_1
        participant_2.private_share = nonce_share_2
        pubkeys = [participant_1.point, participant_2.point]
        coor = MuSigCoordinator(pubkeys)
        coor.register_nonce_share(participant_1.point.sec(), nonce_share_1.public_share)
        coor.register_nonce_share(participant_2.point.sec(), nonce_share_2.public_share)
        context = coor.create_signing_context(msg)
        partial_sig = participant_1.sign(context)
        self.assertTrue(
            context.verify(partial_sig, nonce_share_1.public_share, participant_1.point)
        )

    def test_compute_sig(self):
        participant_1 = MuSigParticipant(PrivateKey(1000))
        participant_2 = MuSigParticipant(PrivateKey(2000))
        msg = b"Hello World!"
        nonce_share_1 = NoncePrivateShare(3000, 4000, participant_1.point)
        nonce_share_2 = NoncePrivateShare(5000, 6000, participant_2.point)
        participant_1.private_share = nonce_share_1
        participant_2.private_share = nonce_share_2
        pubkeys = [participant_1.point, participant_2.point]
        for merkle_root in (
            None,
            b"",
            bytes.fromhex(
                "818c9d665b78324ba673afca23f5f4f5512214ccfd0554fe82c5f99f5a29689b"
            ),
        ):
            coor = MuSigCoordinator(pubkeys, merkle_root)
            coor.register_nonce_share(
                participant_1.point.sec(), nonce_share_1.public_share
            )
            coor.register_nonce_share(
                participant_2.point.sec(), nonce_share_2.public_share
            )
            context = coor.create_signing_context(msg)
            partial_sig_1 = participant_1.sign(context)
            partial_sig_2 = participant_2.sign(context)
            coor.register_partial_sig(participant_1.point.sec(), partial_sig_1)
            coor.register_partial_sig(participant_2.point.sec(), partial_sig_2)
            sig = coor.compute_sig()
            self.assertTrue(context.group_point.verify_schnorr(msg, sig))


class MuSigCoordinator:
    """Coordinator that collects nonces and partial signatures and generates the
    final SchnorrSignature"""
    def __init__(self, participant_points, merkle_root=None, sort=True):
        if len(participant_points) == 0:
            raise ValueError("Need at least one public key")
        # sort the points by their xonly representation and use their even versions
        if sort:
            self.secs = sorted([p.sec() for p in participant_points])
            self.points = [S256Point.parse(c) for c in self.secs]
        else:
            self.secs = [p.sec() for p in participant_points]
            self.points = participant_points
        self.keyagg = KeyAggregator(self.points, merkle_root=merkle_root)
        # convenience
        self.group_point = self.keyagg.group_point
        self.nonce_shares = {}
        self.nonceagg = None
        self.signing_context = None
        self.partial_sigs = {}

    def compute_nonce_point(self, msg):
        # compute nonce share sums, S and T from the nonce shares
        # S = S_1 + S_2 + ... + S_n, T = T_1 + T_2 + ... + T_n
        s = S256Point.sum([share.s for share in self.nonce_shares.values()])
        t = S256Point.sum([share.t for share in self.nonce_shares.values()])
        # the preimage is S || T || P || z, S and T are in sec and P in xonly
        preimage = s.sec() + t.sec() + self.group_point.xonly() + msg
        # nonce_coef (b) is hash_musignoncecoef of the preimage as a big endian int
        b = big_endian_to_int(hash_musignoncecoef(preimage))
        # the nonce point is R=S+bT
        return s + b * t

    def create_signing_context(self, msg):
        """Create the data needed by each participant to sign"""
        self.aggregate_nonce_shares()
        self.signing_context = SigningContext(self.keyagg, self.nonceagg, msg)
        return self.signing_context

    def clear_nonces(self):
        self.nonce_shares = {}

    def register_nonce_share(self, sec, nonce_public_share):
        self.nonce_shares[sec] = nonce_public_share

    def aggregate_nonce_shares(self):
        """Compute the nonce aggregator (S and T)"""
        if self.nonceagg is None:
            for sec in self.secs:
                if not self.nonce_shares.get(sec):
                    raise RuntimeError("Not everyone has registered a nonce")
            self.nonceagg = NonceAggregator.from_nonce_shares(
                self.nonce_shares.values()
            )
        return self.nonceagg

    def register_partial_sig(self, sec, partial_sig):
        """Register the signature share for a particular pubkey"""
        pubkey = S256Point.parse(sec)
        # make sure the partial signature is not too big
        s = big_endian_to_int(partial_sig)
        if s >= N:
            raise ValueError("Partial Sig is too big")
        # make sure the partial sig verifies
        nonce_share = self.nonce_shares[sec]
        if not self.signing_context.verify(partial_sig, nonce_share, pubkey):
            raise ValueError("Partial Signature does not Validate")
        self.partial_sigs[sec] = s

    def compute_sig(self):
        """Aggregates the partial signatures"""
        # sum up the partial signatures to a complete s
        s = sum(self.partial_sigs.values()) % N
        # get the group nonce point (R) from the signing context
        r = self.signing_context.nonce_point
        # if we've tweaked (see self.keyagg.tweak_amount), we need to shift s
        if self.keyagg.tweak_amount:
            # tweak (t) is held in the Key Aggregator
            t = self.keyagg.tweak_amount
            # challenge d = H(R||Q||m)  is in the signing context
            d = self.signing_context.challenge()
            # s = s + d * t if group point is even, s = s - d * t if odd
            if self.group_point.even:
                s = (s + d * t) % N
            else:
                s = (s - d * t) % N
        # create the signature
        signature = SchnorrSignature(r, s)
        # sanity check that the generated signature validates
        if not self.signing_context.group_point.verify_schnorr(
            self.signing_context.msg, signature
        ):
            raise RuntimeError("Signature does not validate")
        # return the signature
        return signature


class NonceAggTest(TestCase):
    def test_compute_nonce_point(self):
        participant_1 = MuSigParticipant(PrivateKey(1000))
        participant_2 = MuSigParticipant(PrivateKey(2000))
        msg = b"Hello World!"
        nonce_share_1 = NoncePrivateShare(3000, 4000, participant_1.point)
        nonce_share_2 = NoncePrivateShare(5000, 6000, participant_2.point)
        pubkeys = [participant_1.point, participant_2.point]
        coor = MuSigCoordinator(pubkeys)
        coor.register_nonce_share(participant_1.point.sec(), nonce_share_1.public_share)
        coor.register_nonce_share(participant_2.point.sec(), nonce_share_2.public_share)
        nonce_point = coor.compute_nonce_point(msg)
        want_sec = "0254d698964537d2f322797ef5f38307516789b22f27da7d5e6855447ea2b50aff"
        self.assertEqual(nonce_point.sec().hex(), want_sec)


class MuSigTest(TestCase):
    def test_key_aggregation(self):
        test_data = {
            "pubkeys": [
                "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
                "03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                "023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66",
                "020000000000000000000000000000000000000000000000000000000000000005",
                "02FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
                "04F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
                "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
            ],
            "tweaks": [
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
                "252E4BD67410A76CDF933D30EAA1608214037F1B105A013ECCD3C5C184A6110B",
            ],
            "valid_test_cases": [
                {
                    "key_indices": [0, 1, 2],
                    "expected": "90539EEDE565F5D054F32CC0C220126889ED1E5D193BAF15AEF344FE59D4610C",
                },
                {
                    "key_indices": [2, 1, 0],
                    "expected": "6204DE8B083426DC6EAF9502D27024D53FC826BF7D2012148A0575435DF54B2B",
                },
                {
                    "key_indices": [0, 0, 0],
                    "expected": "B436E3BAD62B8CD409969A224731C193D051162D8C5AE8B109306127DA3AA935",
                },
                {
                    "key_indices": [0, 0, 1, 1],
                    "expected": "69BC22BFA5D106306E48A20679DE1D7389386124D07571D0D872686028C26A3E",
                },
            ],
            "error_test_cases": [
                {
                    "key_indices": [0, 3],
                    "tweak_indices": [],
                    "is_xonly": [],
                    "error": {
                        "type": "invalid_contribution",
                        "signer": 1,
                        "contrib": "pubkey",
                    },
                    "comment": "Invalid public key",
                },
                {
                    "key_indices": [0, 4],
                    "tweak_indices": [],
                    "is_xonly": [],
                    "error": {
                        "type": "invalid_contribution",
                        "signer": 1,
                        "contrib": "pubkey",
                    },
                    "comment": "Public key exceeds field size",
                },
                {
                    "key_indices": [5, 0],
                    "tweak_indices": [],
                    "is_xonly": [],
                    "error": {
                        "type": "invalid_contribution",
                        "signer": 0,
                        "contrib": "pubkey",
                    },
                    "comment": "First byte of public key is not 2 or 3",
                },
            ],
        }
        for test in test_data["valid_test_cases"]:
            raw_pubkeys = [test_data["pubkeys"][i] for i in test["key_indices"]]
            pubkeys = [S256Point.parse(bytes.fromhex(raw)) for raw in raw_pubkeys]
            keyagg = KeyAggregator(pubkeys)
            self.assertEqual(keyagg.group_point.xonly().hex().upper(), test["expected"])
        for test in test_data["error_test_cases"]:
            with self.assertRaises(ValueError):
                raw_pubkeys = [test_data["pubkeys"][i] for i in test["key_indices"]]
                pubkeys = [S256Point.parse(bytes.fromhex(raw)) for raw in raw_pubkeys]
                keyagg = KeyAggregator(pubkeys)

    def test_nonce_generation(self):
        tests = [
            {
                "rand_": "0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F",
                "sk": "0202020202020202020202020202020202020202020202020202020202020202",
                "pk": "024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766",
                "aggpk": "0707070707070707070707070707070707070707070707070707070707070707",
                "msg": "0101010101010101010101010101010101010101010101010101010101010101",
                "extra_in": "0808080808080808080808080808080808080808080808080808080808080808",
                "expected_secnonce": "B114E502BEAA4E301DD08A50264172C84E41650E6CB726B410C0694D59EFFB6495B5CAF28D045B973D63E3C99A44B807BDE375FD6CB39E46DC4A511708D0E9D2024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766",
                "expected_pubnonce": "02F7BE7089E8376EB355272368766B17E88E7DB72047D05E56AA881EA52B3B35DF02C29C8046FDD0DED4C7E55869137200FBDBFE2EB654267B6D7013602CAED3115A",
            },
            {
                "rand_": "0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F",
                "sk": "0202020202020202020202020202020202020202020202020202020202020202",
                "pk": "024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766",
                "aggpk": "0707070707070707070707070707070707070707070707070707070707070707",
                "msg": b"",
                "extra_in": "0808080808080808080808080808080808080808080808080808080808080808",
                "expected_secnonce": "E862B068500320088138468D47E0E6F147E01B6024244AE45EAC40ACE5929B9F0789E051170B9E705D0B9EB49049A323BBBBB206D8E05C19F46C6228742AA7A9024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766",
                "expected_pubnonce": "023034FA5E2679F01EE66E12225882A7A48CC66719B1B9D3B6C4DBD743EFEDA2C503F3FD6F01EB3A8E9CB315D73F1F3D287CAFBB44AB321153C6287F407600205109",
            },
            {
                "rand_": "0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F",
                "sk": "0202020202020202020202020202020202020202020202020202020202020202",
                "pk": "024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766",
                "aggpk": "0707070707070707070707070707070707070707070707070707070707070707",
                "msg": "2626262626262626262626262626262626262626262626262626262626262626262626262626",
                "extra_in": "0808080808080808080808080808080808080808080808080808080808080808",
                "expected_secnonce": "3221975ACBDEA6820EABF02A02B7F27D3A8EF68EE42787B88CBEFD9AA06AF3632EE85B1A61D8EF31126D4663A00DD96E9D1D4959E72D70FE5EBB6E7696EBA66F024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766",
                "expected_pubnonce": "02E5BBC21C69270F59BD634FCBFA281BE9D76601295345112C58954625BF23793A021307511C79F95D38ACACFF1B4DA98228B77E65AA216AD075E9673286EFB4EAF3",
            },
            {
                "rand_": "0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F",
                "sk": None,
                "pk": "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
                "aggpk": None,
                "msg": None,
                "extra_in": None,
                "expected_secnonce": "89BDD787D0284E5E4D5FC572E49E316BAB7E21E3B1830DE37DFE80156FA41A6D0B17AE8D024C53679699A6FD7944D9C4A366B514BAF43088E0708B1023DD289702F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
                "expected_pubnonce": "02C96E7CB1E8AA5DAC64D872947914198F607D90ECDE5200DE52978AD5DED63C000299EC5117C2D29EDEE8A2092587C3909BE694D5CFF0667D6C02EA4059F7CD9786",
            },
        ]
        for test in tests:
            rand = bytes.fromhex(test["rand_"])
            priv = test["sk"] and PrivateKey(
                big_endian_to_int(bytes.fromhex(test["sk"]))
            )
            pubkey = S256Point.parse(bytes.fromhex(test["pk"]))
            aggregate = test["aggpk"] and S256Point.parse_xonly(
                bytes.fromhex(test["aggpk"])
            )
            msg = test["msg"] and bytes.fromhex(test["msg"])
            extra = test["extra_in"] and bytes.fromhex(test["extra_in"])
            priv_share = NoncePrivateShare.generate_nonce_share(
                pubkey, priv, aggregate, msg, extra, rand
            )
            want_l = big_endian_to_int(bytes.fromhex(test["expected_secnonce"][:64]))
            want_m = big_endian_to_int(bytes.fromhex(test["expected_secnonce"][64:128]))
            want_s = S256Point.parse(bytes.fromhex(test["expected_pubnonce"][:66]))
            want_t = S256Point.parse(bytes.fromhex(test["expected_pubnonce"][66:]))
            self.assertEqual(want_l, priv_share.l)
            self.assertEqual(want_m, priv_share.m)
            self.assertEqual(want_s, priv_share.public_share.s)
            self.assertEqual(want_t, priv_share.public_share.t)

    def test_nonce_aggregation(self):
        test_data = {
            "pnonces": [
                "020151C80F435648DF67A22B749CD798CE54E0321D034B92B709B567D60A42E66603BA47FBC1834437B3212E89A84D8425E7BF12E0245D98262268EBDCB385D50641",
                "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60248C264CDD57D3C24D79990B0F865674EB62A0F9018277A95011B41BFC193B833",
                "020151C80F435648DF67A22B749CD798CE54E0321D034B92B709B567D60A42E6660279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
                "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60379BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
                "04FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60248C264CDD57D3C24D79990B0F865674EB62A0F9018277A95011B41BFC193B833",
                "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60248C264CDD57D3C24D79990B0F865674EB62A0F9018277A95011B41BFC193B831",
                "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A602FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
            ],
            "valid_test_cases": [
                {
                    "pnonce_indices": [0, 1],
                    "expected": "035FE1873B4F2967F52FEA4A06AD5A8ECCBE9D0FD73068012C894E2E87CCB5804B024725377345BDE0E9C33AF3C43C0A29A9249F2F2956FA8CFEB55C8573D0262DC8",
                },
                {
                    "pnonce_indices": [2, 3],
                    "expected": "035FE1873B4F2967F52FEA4A06AD5A8ECCBE9D0FD73068012C894E2E87CCB5804B000000000000000000000000000000000000000000000000000000000000000000",
                    "comment": "Sum of second points encoded in the nonces is point at infinity which is serialized as 33 zero bytes",
                },
            ],
            "error_test_cases": [
                {
                    "pnonce_indices": [0, 4],
                    "error": {
                        "type": "invalid_contribution",
                        "signer": 1,
                        "contrib": "pubnonce",
                    },
                    "comment": "Public nonce from signer 1 is invalid due wrong tag, 0x04, in the first half",
                },
                {
                    "pnonce_indices": [5, 1],
                    "error": {
                        "type": "invalid_contribution",
                        "signer": 0,
                        "contrib": "pubnonce",
                    },
                    "comment": "Public nonce from signer 0 is invalid because the second half does not correspond to an X coordinate",
                },
                {
                    "pnonce_indices": [6, 1],
                    "error": {
                        "type": "invalid_contribution",
                        "signer": 0,
                        "contrib": "pubnonce",
                    },
                    "comment": "Public nonce from signer 0 is invalid because second half exceeds field size",
                },
            ],
        }
        for test in test_data["valid_test_cases"]:
            pubkeys = [
                PrivateKey(i + 1).point for i in range(len(test["pnonce_indices"]))
            ]
            coor = MuSigCoordinator(pubkeys)
            for i, pnonce_index in enumerate(test["pnonce_indices"]):
                raw = bytes.fromhex(test_data["pnonces"][pnonce_index])
                nonce_share = NoncePublicShare.parse(raw)
                coor.register_nonce_share(pubkeys[i].sec(), nonce_share)
            nonceagg = coor.aggregate_nonce_shares()
            self.assertEqual(nonceagg.serialize(), bytes.fromhex(test["expected"]))
        for test in test_data["error_test_cases"]:
            pubkeys = [
                PrivateKey(i + 1).point for i in range(len(test["pnonce_indices"]))
            ]
            coor = MuSigCoordinator(pubkeys)
            with self.assertRaises(ValueError):
                for i, pnonce_index in enumerate(test["pnonce_indices"]):
                    raw = bytes.fromhex(test_data["pnonces"][pnonce_index])
                    nonce_share = NoncePublicShare.parse(raw)
                    coor.register_nonce_share(pubkeys[i].sec(), nonce_share)
                coor.aggregate_nonce_shares()

    def test_signature_aggregation(self):
        test_data = {
            "pubkeys": [
                "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
                "02D2DC6F5DF7C56ACF38C7FA0AE7A759AE30E19B37359DFDE015872324C7EF6E05",
                "03C7FB101D97FF930ACD0C6760852EF64E69083DE0B06AC6335724754BB4B0522C",
                "02352433B21E7E05D3B452B81CAE566E06D2E003ECE16D1074AABA4289E0E3D581",
            ],
            "pnonces": [
                "036E5EE6E28824029FEA3E8A9DDD2C8483F5AF98F7177C3AF3CB6F47CAF8D94AE902DBA67E4A1F3680826172DA15AFB1A8CA85C7C5CC88900905C8DC8C328511B53E",
                "03E4F798DA48A76EEC1C9CC5AB7A880FFBA201A5F064E627EC9CB0031D1D58FC5103E06180315C5A522B7EC7C08B69DCD721C313C940819296D0A7AB8E8795AC1F00",
                "02C0068FD25523A31578B8077F24F78F5BD5F2422AFF47C1FADA0F36B3CEB6C7D202098A55D1736AA5FCC21CF0729CCE852575C06C081125144763C2C4C4A05C09B6",
                "031F5C87DCFBFCF330DEE4311D85E8F1DEA01D87A6F1C14CDFC7E4F1D8C441CFA40277BF176E9F747C34F81B0D9F072B1B404A86F402C2D86CF9EA9E9C69876EA3B9",
                "023F7042046E0397822C4144A17F8B63D78748696A46C3B9F0A901D296EC3406C302022B0B464292CF9751D699F10980AC764E6F671EFCA15069BBE62B0D1C62522A",
                "02D97DDA5988461DF58C5897444F116A7C74E5711BF77A9446E27806563F3B6C47020CBAD9C363A7737F99FA06B6BE093CEAFF5397316C5AC46915C43767AE867C00",
            ],
            "tweaks": [
                "B511DA492182A91B0FFB9A98020D55F260AE86D7ECBD0399C7383D59A5F2AF7C",
                "A815FE049EE3C5AAB66310477FBC8BCCCAC2F3395F59F921C364ACD78A2F48DC",
                "75448A87274B056468B977BE06EB1E9F657577B7320B0A3376EA51FD420D18A8",
            ],
            "psigs": [
                "B15D2CD3C3D22B04DAE438CE653F6B4ECF042F42CFDED7C41B64AAF9B4AF53FB",
                "6193D6AC61B354E9105BBDC8937A3454A6D705B6D57322A5A472A02CE99FCB64",
                "9A87D3B79EC67228CB97878B76049B15DBD05B8158D17B5B9114D3C226887505",
                "66F82EA90923689B855D36C6B7E032FB9970301481B99E01CDB4D6AC7C347A15",
                "4F5AEE41510848A6447DCD1BBC78457EF69024944C87F40250D3EF2C25D33EFE",
                "DDEF427BBB847CC027BEFF4EDB01038148917832253EBC355FC33F4A8E2FCCE4",
                "97B890A26C981DA8102D3BC294159D171D72810FDF7C6A691DEF02F0F7AF3FDC",
                "53FA9E08BA5243CBCB0D797C5EE83BC6728E539EB76C2D0BF0F971EE4E909971",
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            ],
            "msg": "599C67EA410D005B9DA90817CF03ED3B1C868E4DA4EDF00A5880B0082C237869",
            "valid_test_cases": [
                {
                    "aggnonce": "0341432722C5CD0268D829C702CF0D1CBCE57033EED201FD335191385227C3210C03D377F2D258B64AADC0E16F26462323D701D286046A2EA93365656AFD9875982B",
                    "nonce_indices": [0, 1],
                    "key_indices": [0, 1],
                    "tweak_indices": [],
                    "is_xonly": [],
                    "psig_indices": [0, 1],
                    "expected": "041DA22223CE65C92C9A0D6C2CAC828AAF1EEE56304FEC371DDF91EBB2B9EF0912F1038025857FEDEB3FF696F8B99FA4BB2C5812F6095A2E0004EC99CE18DE1E",
                },
                {
                    "aggnonce": "0224AFD36C902084058B51B5D36676BBA4DC97C775873768E58822F87FE437D792028CB15929099EEE2F5DAE404CD39357591BA32E9AF4E162B8D3E7CB5EFE31CB20",
                    "nonce_indices": [0, 2],
                    "key_indices": [0, 2],
                    "tweak_indices": [],
                    "is_xonly": [],
                    "psig_indices": [2, 3],
                    "expected": "1069B67EC3D2F3C7C08291ACCB17A9C9B8F2819A52EB5DF8726E17E7D6B52E9F01800260A7E9DAC450F4BE522DE4CE12BA91AEAF2B4279219EF74BE1D286ADD9",
                },
            ],
            "error_test_cases": [
                {
                    "aggnonce": "02B5AD07AFCD99B6D92CB433FBD2A28FDEB98EAE2EB09B6014EF0F8197CD58403302E8616910F9293CF692C49F351DB86B25E352901F0E237BAFDA11F1C1CEF29FFD",
                    "nonce_indices": [0, 4],
                    "key_indices": [0, 3],
                    "psig_indices": [7, 8],
                    "error": {"type": "invalid_contribution", "signer": 1},
                    "comment": "Partial signature is invalid because it exceeds group size",
                }
            ],
        }
        msg = bytes.fromhex(test_data["msg"])
        for test in test_data["valid_test_cases"]:
            raw_pubkeys = [test_data["pubkeys"][i] for i in test["key_indices"]]
            pubkeys = [S256Point.parse(bytes.fromhex(raw)) for raw in raw_pubkeys]
            coor = MuSigCoordinator(pubkeys, sort=False)
            for i, pnonce_index in enumerate(test["nonce_indices"]):
                raw = bytes.fromhex(test_data["pnonces"][pnonce_index])
                nonce_share = NoncePublicShare.parse(raw)
                coor.register_nonce_share(pubkeys[i].sec(), nonce_share)
            nonceagg = coor.aggregate_nonce_shares()
            self.assertEqual(nonceagg.serialize(), bytes.fromhex(test["aggnonce"]))
            coor.create_signing_context(msg)
            for i, psig_index in enumerate(test["psig_indices"]):
                raw = test_data["psigs"][psig_index]
                partial_s = bytes.fromhex(raw)
                coor.register_partial_sig(pubkeys[i].sec(), partial_s)
            schnorr_signature = coor.compute_sig()
            self.assertEqual(
                schnorr_signature.serialize().hex().upper(), test["expected"]
            )
        for test in test_data["error_test_cases"]:
            raw_pubkeys = [test_data["pubkeys"][i] for i in test["key_indices"]]
            pubkeys = [S256Point.parse(bytes.fromhex(raw)) for raw in raw_pubkeys]
            coor = MuSigCoordinator(pubkeys, sort=False)
            for i, pnonce_index in enumerate(test["nonce_indices"]):
                raw = bytes.fromhex(test_data["pnonces"][pnonce_index])
                nonce_share = NoncePublicShare.parse(raw)
                coor.register_nonce_share(pubkeys[i].sec(), nonce_share)
            nonceagg = coor.aggregate_nonce_shares()
            self.assertEqual(nonceagg.serialize(), bytes.fromhex(test["aggnonce"]))
            coor.create_signing_context(msg)
            with self.assertRaises(ValueError):
                for i, psig_index in enumerate(test["psig_indices"]):
                    raw = test_data["psigs"][psig_index]
                    partial_s = bytes.fromhex(raw)
                    coor.register_partial_sig(pubkeys[i].sec(), partial_s)

    def test_sign_verify(self):
        test_data = {
            "sk": "7FB9E0E687ADA1EEBF7ECFE2F21E73EBDB51A7D450948DFE8D76D7F2D1007671",
            "pubkeys": [
                "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
                "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
                "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA661",
                "020000000000000000000000000000000000000000000000000000000000000007",
            ],
            "secnonces": [
                "508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F703935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
                "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
            ],
            "pnonces": [
                "0337C87821AFD50A8644D820A8F3E02E499C931865C2360FB43D0A0D20DAFE07EA0287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480",
                "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817980279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
                "032DE2662628C90B03F5E720284EB52FF7D71F4284F627B68A853D78C78E1FFE9303E4C5524E83FFE1493B9077CF1CA6BEB2090C93D930321071AD40B2F44E599046",
                "0237C87821AFD50A8644D820A8F3E02E499C931865C2360FB43D0A0D20DAFE07EA0387BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480",
                "0200000000000000000000000000000000000000000000000000000000000000090287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480",
            ],
            "aggnonces": [
                "028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9",
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "048465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9",
                "028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61020000000000000000000000000000000000000000000000000000000000000009",
                "028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD6102FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
            ],
            "msgs": [
                "F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF",
                "",
                "2626262626262626262626262626262626262626262626262626262626262626262626262626",
            ],
            "valid_test_cases": [
                {
                    "key_indices": [0, 1, 2],
                    "nonce_indices": [0, 1, 2],
                    "aggnonce_index": 0,
                    "msg_index": 0,
                    "signer_index": 0,
                    "expected": "012ABBCB52B3016AC03AD82395A1A415C48B93DEF78718E62A7A90052FE224FB",
                },
                {
                    "key_indices": [1, 0, 2],
                    "nonce_indices": [1, 0, 2],
                    "aggnonce_index": 0,
                    "msg_index": 0,
                    "signer_index": 1,
                    "expected": "9FF2F7AAA856150CC8819254218D3ADEEB0535269051897724F9DB3789513A52",
                },
                {
                    "key_indices": [1, 2, 0],
                    "nonce_indices": [1, 2, 0],
                    "aggnonce_index": 0,
                    "msg_index": 0,
                    "signer_index": 2,
                    "expected": "FA23C359F6FAC4E7796BB93BC9F0532A95468C539BA20FF86D7C76ED92227900",
                },
                {
                    "key_indices": [0, 1],
                    "nonce_indices": [0, 3],
                    "aggnonce_index": 1,
                    "msg_index": 0,
                    "signer_index": 0,
                    "expected": "AE386064B26105404798F75DE2EB9AF5EDA5387B064B83D049CB7C5E08879531",
                    "comment": "Both halves of aggregate nonce correspond to point at infinity",
                },
                {
                    "key_indices": [0, 1, 2],
                    "nonce_indices": [0, 1, 2],
                    "aggnonce_index": 0,
                    "msg_index": 1,
                    "signer_index": 0,
                    "expected": "D7D63FFD644CCDA4E62BC2BC0B1D02DD32A1DC3030E155195810231D1037D82D",
                    "comment": "Empty message",
                },
                {
                    "key_indices": [0, 1, 2],
                    "nonce_indices": [0, 1, 2],
                    "aggnonce_index": 0,
                    "msg_index": 2,
                    "signer_index": 0,
                    "expected": "E184351828DA5094A97C79CABDAAA0BFB87608C32E8829A4DF5340A6F243B78C",
                    "comment": "38-byte message",
                },
            ],
            "sign_error_test_cases": [
                {
                    "key_indices": [1, 2],
                    "aggnonce_index": 0,
                    "msg_index": 0,
                    "secnonce_index": 0,
                    "error": {
                        "type": "value",
                        "message": "The signer's pubkey must be included in the list of pubkeys.",
                    },
                    "comment": "The signers pubkey is not in the list of pubkeys. This test case is optional: it can be skipped by implementations that do not check that the signer's pubkey is included in the list of pubkeys.",
                },
                {
                    "key_indices": [1, 0, 3],
                    "aggnonce_index": 0,
                    "msg_index": 0,
                    "secnonce_index": 0,
                    "error": {
                        "type": "invalid_contribution",
                        "signer": 2,
                        "contrib": "pubkey",
                    },
                    "comment": "Signer 2 provided an invalid public key",
                },
                {
                    "key_indices": [1, 2, 0],
                    "aggnonce_index": 2,
                    "msg_index": 0,
                    "secnonce_index": 0,
                    "error": {
                        "type": "invalid_contribution",
                        "signer": None,
                        "contrib": "aggnonce",
                    },
                    "comment": "Aggregate nonce is invalid due wrong tag, 0x04, in the first half",
                },
                {
                    "key_indices": [1, 2, 0],
                    "aggnonce_index": 3,
                    "msg_index": 0,
                    "secnonce_index": 0,
                    "error": {
                        "type": "invalid_contribution",
                        "signer": None,
                        "contrib": "aggnonce",
                    },
                    "comment": "Aggregate nonce is invalid because the second half does not correspond to an X coordinate",
                },
                {
                    "key_indices": [1, 2, 0],
                    "aggnonce_index": 4,
                    "msg_index": 0,
                    "secnonce_index": 0,
                    "error": {
                        "type": "invalid_contribution",
                        "signer": None,
                        "contrib": "aggnonce",
                    },
                    "comment": "Aggregate nonce is invalid because second half exceeds field size",
                },
                {
                    "key_indices": [0, 1, 2],
                    "aggnonce_index": 0,
                    "msg_index": 0,
                    "signer_index": 0,
                    "secnonce_index": 1,
                    "error": {
                        "type": "value",
                        "message": "first secnonce value is out of range.",
                    },
                    "comment": "Secnonce is invalid which may indicate nonce reuse",
                },
            ],
            "verify_fail_test_cases": [
                {
                    "sig": "97AC833ADCB1AFA42EBF9E0725616F3C9A0D5B614F6FE283CEAAA37A8FFAF406",
                    "key_indices": [0, 1, 2],
                    "nonce_indices": [0, 1, 2],
                    "msg_index": 0,
                    "signer_index": 0,
                    "comment": "Wrong signature (which is equal to the negation of valid signature)",
                },
                {
                    "sig": "68537CC5234E505BD14061F8DA9E90C220A181855FD8BDB7F127BB12403B4D3B",
                    "key_indices": [0, 1, 2],
                    "nonce_indices": [0, 1, 2],
                    "msg_index": 0,
                    "signer_index": 1,
                    "comment": "Wrong signer",
                },
                {
                    "sig": "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
                    "key_indices": [0, 1, 2],
                    "nonce_indices": [0, 1, 2],
                    "msg_index": 0,
                    "signer_index": 0,
                    "comment": "Signature exceeds group size",
                },
            ],
            "verify_error_test_cases": [
                {
                    "sig": "68537CC5234E505BD14061F8DA9E90C220A181855FD8BDB7F127BB12403B4D3B",
                    "key_indices": [0, 1, 2],
                    "nonce_indices": [4, 1, 2],
                    "msg_index": 0,
                    "signer_index": 0,
                    "error": {
                        "type": "invalid_contribution",
                        "signer": 0,
                        "contrib": "pubnonce",
                    },
                    "comment": "Invalid pubnonce",
                },
                {
                    "sig": "68537CC5234E505BD14061F8DA9E90C220A181855FD8BDB7F127BB12403B4D3B",
                    "key_indices": [3, 1, 2],
                    "nonce_indices": [0, 1, 2],
                    "msg_index": 0,
                    "signer_index": 0,
                    "error": {
                        "type": "invalid_contribution",
                        "signer": 0,
                        "contrib": "pubkey",
                    },
                    "comment": "Invalid pubkey",
                },
            ],
        }
        secret = big_endian_to_int(bytes.fromhex(test_data["sk"]))
        private_key = PrivateKey(secret)
        raw = bytes.fromhex(test_data["secnonces"][0])
        nonce_private_share = NoncePrivateShare.parse(raw)
        participant = MuSigParticipant(private_key, nonce_private_share)
        for test in test_data["sign_error_test_cases"]:
            with self.assertRaises(ValueError):
                msg = bytes.fromhex(test_data["msgs"][test["msg_index"]])
                raw_pubkeys = [test_data["pubkeys"][i] for i in test["key_indices"]]
                pubkeys = [S256Point.parse(bytes.fromhex(raw)) for raw in raw_pubkeys]
                secnonce = bytes.fromhex(test_data["secnonces"][test["secnonce_index"]])
                nonce_private_share = NoncePrivateShare.parse(secnonce)
                coor = MuSigCoordinator(pubkeys, sort=False)
                raw_aggnonce = bytes.fromhex(
                    test_data["aggnonces"][test["aggnonce_index"]]
                )
                coor.nonceagg = NonceAggregator.parse(raw_aggnonce)
                context = coor.create_signing_context(msg)
                participant.sign(context)
        for test in test_data["valid_test_cases"]:
            msg = bytes.fromhex(test_data["msgs"][test["msg_index"]])
            want_aggnonce = test_data["aggnonces"][test["aggnonce_index"]]
            raw_pubkeys = [test_data["pubkeys"][i] for i in test["key_indices"]]
            pubkeys = [S256Point.parse(bytes.fromhex(raw)) for raw in raw_pubkeys]
            signer_pubkey = pubkeys[test["signer_index"]]
            coor = MuSigCoordinator(pubkeys, sort=False)
            for i, pnonce_index in enumerate(test["nonce_indices"]):
                raw = bytes.fromhex(test_data["pnonces"][pnonce_index])
                nonce_share = NoncePublicShare.parse(raw)
                coor.register_nonce_share(pubkeys[i].sec(), nonce_share)
            nonceagg = coor.aggregate_nonce_shares()
            self.assertEqual(nonceagg.serialize(), bytes.fromhex(want_aggnonce))
            context = coor.create_signing_context(msg)
            partial_sig = participant.sign(context)
            self.assertEqual(partial_sig.hex().upper(), test["expected"])
            coor.register_partial_sig(signer_pubkey.sec(), partial_sig)
        cases = [
            *test_data["verify_fail_test_cases"],
            *test_data["verify_error_test_cases"],
        ]
        for test in cases:
            with self.assertRaises(ValueError):
                msg = bytes.fromhex(test_data["msgs"][test["msg_index"]])
                raw_pubkeys = [test_data["pubkeys"][i] for i in test["key_indices"]]
                pubkeys = [S256Point.parse(bytes.fromhex(raw)) for raw in raw_pubkeys]
                signer_pubkey = pubkeys[test["signer_index"]]
                coor = MuSigCoordinator(pubkeys, sort=False)
                for i, pnonce_index in enumerate(test["nonce_indices"]):
                    raw = bytes.fromhex(test_data["pnonces"][pnonce_index])
                    nonce_share = NoncePublicShare.parse(raw)
                    coor.register_nonce_share(pubkeys[i].sec(), nonce_share)
                context = coor.create_signing_context(msg)
                partial_sig = bytes.fromhex(test["sig"])
                coor.register_partial_sig(signer_pubkey.sec(), partial_sig)
