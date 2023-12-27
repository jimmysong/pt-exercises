from unittest import TestCase, skip

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


class KeyAggContext:
    def __init__(self, points, g_acc=1, t_acc=0):
        self.points = points
        self.g_acc = g_acc
        self.t_acc = t_acc
        # compute the aggregated key group commitment, L
        self.secs = [p.sec() for p in self.points]
        self.group_commitment = hash_keyagglist(b"".join(self.secs))
        # The coefficient for each public key is H(L||P), which we compute
        self.coefs = [self.keyagg_coefficient(point.sec()) for point in self.points]
        # aggregate point
        self.group_point = S256Point.combine([c * p for c, p in zip(self.coefs, self.points)])

    def keyagg_coefficient(self, sec):
        if sec not in [p.sec() for p in self.points]:
            raise ValueError(f"{sec.hex()} is not a participant")
        for p in self.points:
            if p != self.points[0]:
                second_point = p
                break
        else:
            second_point = S256Point(None, None)
        if sec == second_point.sec():
            return 1
        return big_endian_to_int(hash_keyaggcoef(self.group_commitment + sec))

    def apply_tweak(self, tweak):
        if tweak.xonly and self.group_point.parity:
            p = -1 * self.group_point
            g = -1
        else:
            p = self.group_point
            g = 1
        t = big_endian_to_int(tweak.amount)
        if t >= N:
            raise ValueError("Tweak is too large")
        new_point = p + t
        if new_point.x is None:
            raise ValueError("Tweaked Point is point at infinity")
        self.group_point = new_point
        self.g_acc *= g
        self.t_acc = (g * self.t_acc + t) % N


class SigningContext:
    def __init__(self, points, msg, agg_nonce, tweaks=None):
        self.keyagg_context = KeyAggContext(points)
        self.msg = msg
        self.agg_nonce = agg_nonce
        if tweaks is None:
            self.tweaks = []
        else:
            self.tweaks = tweaks
        for tweak in self.tweaks:
            self.keyagg_context.apply_tweak(tweak)
        self.group_point = self.keyagg_context.group_point

    def keyagg_coefficient(self, sec):
        return self.keyagg_context.keyagg_coefficient(sec)

    def nonce_coef(self):
        preimage = self.agg_nonce.serialize() + self.group_point.xonly() + self.msg
        return big_endian_to_int(hash_musignoncecoef(preimage))

    def group_r(self):
        return self.agg_nonce.compute_r(self.nonce_coef())

    def challenge(self):
        preimage = self.group_r().xonly() + self.group_point.xonly() + self.msg
        return big_endian_to_int(hash_challenge(preimage))

    def verify(self, partial_sig, nonce_public_share, point):
        working_r = nonce_public_share.r(self.nonce_coef())
        if self.group_r().parity:
            working_r = -1 * working_r
        keyagg_coef = self.keyagg_context.keyagg_coefficient(point.sec())
        if self.group_point.parity:
            g = -1 * self.keyagg_context.g_acc
        else:
            g = self.keyagg_context.g_acc
        product = keyagg_coef * g * self.challenge() % N
        s = big_endian_to_int(partial_sig)
        if s * G != S256Point.combine([working_r, product * point]):
            return False
        return True


class Tweak:
    def __init__(self, amount, xonly=True):
        self.amount = amount
        self.xonly = xonly


class AggNonce:
    def __init__(self, n1, n2):
        self.n1 = n1
        self.n2 = n2

    def serialize(self):
        return self.n1.sec() + self.n2.sec()

    def compute_r(self, coef):
        return self.n1 + coef * self.n2

    @classmethod
    def parse(cls, raw):
        n1 = S256Point.parse(raw[:33])
        n2 = S256Point.parse(raw[33:])
        return cls(n1, n2)


class NoncePrivateShare:
    def __init__(self, k1, k2, pubkey):
        if k1 <= 0 or k1 >= N or k2 <= 0 or k2 >= N:
            raise ValueError("nonce is out of range")
        self.k1 = k1
        self.k2 = k2
        self.pubkey = pubkey
        self.public_share = NoncePublicShare(k1 * G, k2 * G)

    def negate(self):
        return self.__class__(N - self.k1, N - self.k2, self.pubkey)

    def k(self, coefficient):
        return (self.k1 + coefficient * self.k2) % N

    @classmethod
    def parse(cls, b):
        k1 = big_endian_to_int(b[:32])
        k2 = big_endian_to_int(b[32:64])
        pubkey = S256Point.parse(b[64:])
        return cls(k1, k2, pubkey)

    @classmethod
    def generate_nonce(cls, pubkey, priv=None, aggregate_pubkey=None, msg=None, extra=None, rand=None):
        if rand is None:
            rand = randbelow(N)
        if priv:
            rand = xor_bytes(int_to_big_endian(priv.secret, 32), hash_musigaux(rand))
        if aggregate_pubkey is None:
            agg = b''
        else:
            agg = aggregate_pubkey.xonly()
        if msg is None:
            msg_prefixed = b"\x00"
        else:
            msg_prefixed = b"\x01" + int_to_big_endian(len(msg), 8) + msg
        if extra is None:
            extra = b""
        to_hash = rand + b"\x21" + pubkey.sec() + int_to_big_endian(len(agg), 1) + agg + msg_prefixed + int_to_big_endian(len(extra), 4) + extra
        k1 = big_endian_to_int(hash_musignonce(to_hash + b"\x00")) % N
        k2 = big_endian_to_int(hash_musignonce(to_hash + b"\x01")) % N
        return cls(k1, k2, pubkey)


class NoncePublicShare:
    def __init__(self, r1, r2):
        self.r1 = r1
        self.r2 = r2

    def r(self, coefficient):
        return self.r1 + coefficient * self.r2

    @classmethod
    def parse(cls, b):
        r1 = S256Point.parse(b[:33])
        r2 = S256Point.parse(b[33:])
        return cls(r1, r2)

    @classmethod
    def sum(cls, public_shares):
        sum_1 = S256Point.combine([p.r1 for p in public_shares])
        sum_2 = S256Point.combine([p.r2 for p in public_shares])
        return sum_1, sum_2


class MuSigParticipant:

    def __init__(self, private_key, private_share=None):
        self.private_key = private_key
        self.point = private_key.point
        self.private_share = private_share
        if self.point != self.private_share.pubkey:
            raise ValueError("Nonce does not correspond to the participant")

    def generate_nonce(self, aggregate_pubkey=None, msg=None, extra=None, rand=None):
        self.private_share = NoncePrivateShare.generate(self.point, self.private_key.secret, aggregate_pubkey, msg, extra, rand)
        return self.private_share.public_share

    def sign(self, context):
        if context.group_r().parity:
            negated = self.private_share.negate()
            working_nonce = negated.k1 + context.nonce_coef() * negated.k2
        else:
            working_nonce = self.private_share.k1 + context.nonce_coef() * self.private_share.k2
        keyagg_coef = context.keyagg_coefficient(self.point.sec())
        g_acc = context.keyagg_context.g_acc
        if context.group_point.parity:
            g = -1 * g_acc
            working_secret = (-1 * g_acc * self.private_key.secret) % N
        else:
            g = g_acc
            working_secret = (g_acc * self.private_key.secret) % N
        s = (working_nonce + keyagg_coef * context.challenge() * working_secret) % N
        partial_sig = int_to_big_endian(s, 32)
        if not context.verify(partial_sig, self.private_share.public_share, self.point):
            raise RuntimeError("failed to verify")
        return partial_sig


class MuSigCoordinator:

    def __init__(self, participant_points, sort=True):
        if len(participant_points) == 0:
            raise ValueError("Need at least one public key")
        # sort the points by their xonly representation and use their even versions
        if sort:
            self.secs = sorted([p.sec() for p in participant_points])
            self.points = [S256Point.parse(c) for c in self.secs]
        else:
            self.secs = [p.sec() for p in participant_points]
            self.points = participant_points
        self.nonce_shares = {}
        self.agg_nonce = None
        self.sig_shares = {}
        self.signing_context = None

    def create_signing_context(self, msg, tweaks=None):
        agg_nonce = self.compute_nonce()
        self.signing_context = SigningContext(self.points, msg, agg_nonce, tweaks)
        return self.signing_context

    def clear_nonces(self):
        self.nonce_shares = {}

    def register_nonce_share(self, sec, nonce_public_share):
        self.nonce_shares[sec] = nonce_public_share

    def compute_nonce(self):
        if self.agg_nonce is None:
            for sec in self.secs:
                if not self.nonce_shares.get(sec):
                    raise RuntimeError("Not everyone has registered a nonce")
            n1, n2 = NoncePublicShare.sum(self.nonce_shares.values())
            self.agg_nonce = AggNonce(n1, n2)
        return self.agg_nonce

    def clear_sigs(self):
        self.sig_shares = {}

    def register_sig_share(self, sec, sig_share):
        pubkey = S256Point.parse(sec)
        s_share = big_endian_to_int(sig_share)
        if s_share >= N:
            raise ValueError("Sig share is too big")
        nonce_share = self.nonce_shares[sec]
        if not self.signing_context.verify(sig_share, nonce_share, pubkey):
            raise ValueError("Signature Share does not Validate")
        self.sig_shares[sec] = s_share

    def compute_sig(self, msg):
        for pubkey in self.nonce_shares.keys():
            if not self.nonce_shares.get(pubkey):
                raise RuntimeError("Not everyone has registered a nonce")
        s = sum(self.sig_shares.values()) % N
        group_r = self.signing_context.group_r()
        t_acc = self.signing_context.keyagg_context.t_acc
        if t_acc:
            e = self.signing_context.challenge()
            if self.signing_context.group_point.parity:
                e *= -1
            s = (s + e * t_acc) % N
        signature = SchnorrSignature(group_r, s)
        if not self.signing_context.group_point.verify_schnorr(msg, signature):
            raise RuntimeError("Signature does not validate")
        return signature


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
                "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9"
            ],
            "tweaks": [
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
                "252E4BD67410A76CDF933D30EAA1608214037F1B105A013ECCD3C5C184A6110B"
            ],
            "valid_test_cases": [
                {
                    "key_indices": [0, 1, 2],
                    "expected": "90539EEDE565F5D054F32CC0C220126889ED1E5D193BAF15AEF344FE59D4610C"
                },
                {
                    "key_indices": [2, 1, 0],
                    "expected": "6204DE8B083426DC6EAF9502D27024D53FC826BF7D2012148A0575435DF54B2B"
                },
                {
                    "key_indices": [0, 0, 0],
                    "expected": "B436E3BAD62B8CD409969A224731C193D051162D8C5AE8B109306127DA3AA935"
                },
                {
                    "key_indices": [0, 0, 1, 1],
                    "expected": "69BC22BFA5D106306E48A20679DE1D7389386124D07571D0D872686028C26A3E"
                }
            ],
            "error_test_cases": [
                {
                    "key_indices": [0, 3],
                    "tweak_indices": [],
                    "is_xonly": [],
                    "error": {
                        "type": "invalid_contribution",
                        "signer": 1,
                        "contrib": "pubkey"
                    },
                    "comment": "Invalid public key"
                },
                {
                    "key_indices": [0, 4],
                    "tweak_indices": [],
                    "is_xonly": [],
                    "error": {
                        "type": "invalid_contribution",
                        "signer": 1,
                        "contrib": "pubkey"
                    },
                    "comment": "Public key exceeds field size"
                },
                {
                    "key_indices": [5, 0],
                    "tweak_indices": [],
                    "is_xonly": [],
                    "error": {
                        "type": "invalid_contribution",
                        "signer": 0,
                        "contrib": "pubkey"
                    },
                    "comment": "First byte of public key is not 2 or 3"
                },
                {
                    "key_indices": [0, 1],
                    "tweak_indices": [0],
                    "is_xonly": [True],
                    "error": {
                        "type": "value",
                        "message": "The tweak must be less than n."
                    },
                    "comment": "Tweak is out of range"
                },
                {
                    "key_indices": [6],
                    "tweak_indices": [1],
                    "is_xonly": [False],
                    "error": {
                        "type": "value",
                        "message": "The result of tweaking cannot be infinity."
                    },
                    "comment": "Intermediate tweaking result is point at infinity"
                }
            ]
        }
        for test in test_data["valid_test_cases"]:
            raw_pubkeys = [test_data["pubkeys"][i] for i in test["key_indices"]]
            pubkeys = [S256Point.parse(bytes.fromhex(raw)) for raw in raw_pubkeys]
            coor = MuSigCoordinator(pubkeys, sort=False)
            context = KeyAggContext(pubkeys)
            self.assertEqual(context.group_point.xonly().hex().upper(), test["expected"])
        for test in test_data["error_test_cases"]:
            with self.assertRaises(ValueError):
                raw_pubkeys = [test_data["pubkeys"][i] for i in test["key_indices"]]
                pubkeys = [S256Point.parse(bytes.fromhex(raw)) for raw in raw_pubkeys]
                raw_tweaks = [test_data["tweaks"][i] for i in test["tweak_indices"]]
                tweaks = [Tweak(bytes.fromhex(raw), xonly) for raw, xonly in zip(raw_tweaks, test["is_xonly"])]
                context = KeyAggContext(pubkeys)
                for tweak in tweaks:
                    context.apply_tweak(tweak)

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
                "expected_pubnonce": "02F7BE7089E8376EB355272368766B17E88E7DB72047D05E56AA881EA52B3B35DF02C29C8046FDD0DED4C7E55869137200FBDBFE2EB654267B6D7013602CAED3115A"
            },
            {
                "rand_": "0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F",
                "sk": "0202020202020202020202020202020202020202020202020202020202020202",
                "pk": "024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766",
                "aggpk": "0707070707070707070707070707070707070707070707070707070707070707",
                "msg": b'',
                "extra_in": "0808080808080808080808080808080808080808080808080808080808080808",
                "expected_secnonce": "E862B068500320088138468D47E0E6F147E01B6024244AE45EAC40ACE5929B9F0789E051170B9E705D0B9EB49049A323BBBBB206D8E05C19F46C6228742AA7A9024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766",
                "expected_pubnonce": "023034FA5E2679F01EE66E12225882A7A48CC66719B1B9D3B6C4DBD743EFEDA2C503F3FD6F01EB3A8E9CB315D73F1F3D287CAFBB44AB321153C6287F407600205109"
            },
            {
                "rand_": "0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F",
                "sk": "0202020202020202020202020202020202020202020202020202020202020202",
                "pk": "024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766",
                "aggpk": "0707070707070707070707070707070707070707070707070707070707070707",
                "msg": "2626262626262626262626262626262626262626262626262626262626262626262626262626",
                "extra_in": "0808080808080808080808080808080808080808080808080808080808080808",
                "expected_secnonce": "3221975ACBDEA6820EABF02A02B7F27D3A8EF68EE42787B88CBEFD9AA06AF3632EE85B1A61D8EF31126D4663A00DD96E9D1D4959E72D70FE5EBB6E7696EBA66F024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766",
                "expected_pubnonce": "02E5BBC21C69270F59BD634FCBFA281BE9D76601295345112C58954625BF23793A021307511C79F95D38ACACFF1B4DA98228B77E65AA216AD075E9673286EFB4EAF3"
            },
            {
                "rand_": "0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F",
                "sk": None,
                "pk": "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
                "aggpk": None,
                "msg": None,
                "extra_in": None,
                "expected_secnonce": "89BDD787D0284E5E4D5FC572E49E316BAB7E21E3B1830DE37DFE80156FA41A6D0B17AE8D024C53679699A6FD7944D9C4A366B514BAF43088E0708B1023DD289702F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
                "expected_pubnonce": "02C96E7CB1E8AA5DAC64D872947914198F607D90ECDE5200DE52978AD5DED63C000299EC5117C2D29EDEE8A2092587C3909BE694D5CFF0667D6C02EA4059F7CD9786"
            }
        ]
        for test in tests:
            rand = bytes.fromhex(test["rand_"])
            priv = test["sk"] and PrivateKey(big_endian_to_int(bytes.fromhex(test["sk"])))
            pubkey = S256Point.parse(bytes.fromhex(test["pk"]))
            aggregate = test["aggpk"] and S256Point.parse_xonly(bytes.fromhex(test["aggpk"]))
            msg = test["msg"] and bytes.fromhex(test["msg"])
            extra = test["extra_in"] and bytes.fromhex(test["extra_in"])
            priv_share = NoncePrivateShare.generate_nonce(pubkey, priv, aggregate, msg, extra, rand)
            want_k1 = big_endian_to_int(bytes.fromhex(test["expected_secnonce"][:64]))
            want_k2 = big_endian_to_int(bytes.fromhex(test["expected_secnonce"][64:128]))
            want_r1 = S256Point.parse(bytes.fromhex(test["expected_pubnonce"][:66]))
            want_r2 = S256Point.parse(bytes.fromhex(test["expected_pubnonce"][66:]))
            self.assertEqual(want_k1, priv_share.k1)
            self.assertEqual(want_k2, priv_share.k2)
            self.assertEqual(want_r1, priv_share.public_share.r1)
            self.assertEqual(want_r2, priv_share.public_share.r2)

    def test_nonce_aggregation(self):
        test_data = {
            "pnonces": [
                "020151C80F435648DF67A22B749CD798CE54E0321D034B92B709B567D60A42E66603BA47FBC1834437B3212E89A84D8425E7BF12E0245D98262268EBDCB385D50641",
                "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60248C264CDD57D3C24D79990B0F865674EB62A0F9018277A95011B41BFC193B833",
                "020151C80F435648DF67A22B749CD798CE54E0321D034B92B709B567D60A42E6660279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
                "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60379BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
                "04FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60248C264CDD57D3C24D79990B0F865674EB62A0F9018277A95011B41BFC193B833",
                "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60248C264CDD57D3C24D79990B0F865674EB62A0F9018277A95011B41BFC193B831",
                "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A602FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30"
            ],
            "valid_test_cases": [
                {
                    "pnonce_indices": [0, 1],
                    "expected": "035FE1873B4F2967F52FEA4A06AD5A8ECCBE9D0FD73068012C894E2E87CCB5804B024725377345BDE0E9C33AF3C43C0A29A9249F2F2956FA8CFEB55C8573D0262DC8"
                },
                {
                    "pnonce_indices": [2, 3],
                    "expected": "035FE1873B4F2967F52FEA4A06AD5A8ECCBE9D0FD73068012C894E2E87CCB5804B000000000000000000000000000000000000000000000000000000000000000000",
                    "comment": "Sum of second points encoded in the nonces is point at infinity which is serialized as 33 zero bytes"
                }
            ],
            "error_test_cases": [
                {
                    "pnonce_indices": [0, 4],
                    "error": {
                        "type": "invalid_contribution",
                        "signer": 1,
                        "contrib": "pubnonce"
                    },
                    "comment": "Public nonce from signer 1 is invalid due wrong tag, 0x04, in the first half"
                },
                {
                    "pnonce_indices": [5, 1],
                    "error": {
                        "type": "invalid_contribution",
                        "signer": 0,
                        "contrib": "pubnonce"
                    },
                    "comment": "Public nonce from signer 0 is invalid because the second half does not correspond to an X coordinate"
                },
                {
                    "pnonce_indices": [6, 1],
                    "error": {
                        "type": "invalid_contribution",
                        "signer": 0,
                        "contrib": "pubnonce"
                    },
                    "comment": "Public nonce from signer 0 is invalid because second half exceeds field size"
                }
            ]
        }
        for test in test_data["valid_test_cases"]:
            pubkeys = [PrivateKey(i+1).point for i in range(len(test["pnonce_indices"]))]
            coor = MuSigCoordinator(pubkeys)
            for i, pnonce_index in enumerate(test["pnonce_indices"]):
                raw = bytes.fromhex(test_data["pnonces"][pnonce_index])
                nonce_share = NoncePublicShare.parse(raw)
                coor.register_nonce_share(pubkeys[i].sec(), nonce_share)
            agg_nonce = coor.compute_nonce()
            self.assertEqual(agg_nonce.serialize(), bytes.fromhex(test["expected"]))
        for test in test_data["error_test_cases"]:
            coor.clear_nonces()
            with self.assertRaises(ValueError):
                for i, pnonce_index in enumerate(test["pnonce_indices"]):
                    raw = bytes.fromhex(test_data["pnonces"][pnonce_index])
                    nonce_share = NoncePublicShare.parse(raw)
                    coor.register_nonce_share(pubkeys[i].sec(), nonce_share)
                coor.compute_nonce()

    def test_signature_aggregation(self):
        test_data = {
            "pubkeys": [
                "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
                "02D2DC6F5DF7C56ACF38C7FA0AE7A759AE30E19B37359DFDE015872324C7EF6E05",
                "03C7FB101D97FF930ACD0C6760852EF64E69083DE0B06AC6335724754BB4B0522C",
                "02352433B21E7E05D3B452B81CAE566E06D2E003ECE16D1074AABA4289E0E3D581"
            ],
            "pnonces": [
                "036E5EE6E28824029FEA3E8A9DDD2C8483F5AF98F7177C3AF3CB6F47CAF8D94AE902DBA67E4A1F3680826172DA15AFB1A8CA85C7C5CC88900905C8DC8C328511B53E",
                "03E4F798DA48A76EEC1C9CC5AB7A880FFBA201A5F064E627EC9CB0031D1D58FC5103E06180315C5A522B7EC7C08B69DCD721C313C940819296D0A7AB8E8795AC1F00",
                "02C0068FD25523A31578B8077F24F78F5BD5F2422AFF47C1FADA0F36B3CEB6C7D202098A55D1736AA5FCC21CF0729CCE852575C06C081125144763C2C4C4A05C09B6",
                "031F5C87DCFBFCF330DEE4311D85E8F1DEA01D87A6F1C14CDFC7E4F1D8C441CFA40277BF176E9F747C34F81B0D9F072B1B404A86F402C2D86CF9EA9E9C69876EA3B9",
                "023F7042046E0397822C4144A17F8B63D78748696A46C3B9F0A901D296EC3406C302022B0B464292CF9751D699F10980AC764E6F671EFCA15069BBE62B0D1C62522A",
                "02D97DDA5988461DF58C5897444F116A7C74E5711BF77A9446E27806563F3B6C47020CBAD9C363A7737F99FA06B6BE093CEAFF5397316C5AC46915C43767AE867C00"
            ],
            "tweaks": [
                "B511DA492182A91B0FFB9A98020D55F260AE86D7ECBD0399C7383D59A5F2AF7C",
                "A815FE049EE3C5AAB66310477FBC8BCCCAC2F3395F59F921C364ACD78A2F48DC",
                "75448A87274B056468B977BE06EB1E9F657577B7320B0A3376EA51FD420D18A8"
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
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
            ],
            "msg": "599C67EA410D005B9DA90817CF03ED3B1C868E4DA4EDF00A5880B0082C237869",
            "valid_test_cases": [
                {
                    "aggnonce": "0341432722C5CD0268D829C702CF0D1CBCE57033EED201FD335191385227C3210C03D377F2D258B64AADC0E16F26462323D701D286046A2EA93365656AFD9875982B",
                    "nonce_indices": [
                        0,
                        1
                    ],
                    "key_indices": [
                        0,
                        1
                    ],
                    "tweak_indices": [],
                    "is_xonly": [],
                    "psig_indices": [
                        0,
                        1
                    ],
                    "expected": "041DA22223CE65C92C9A0D6C2CAC828AAF1EEE56304FEC371DDF91EBB2B9EF0912F1038025857FEDEB3FF696F8B99FA4BB2C5812F6095A2E0004EC99CE18DE1E"
                },
                {
                    "aggnonce": "0224AFD36C902084058B51B5D36676BBA4DC97C775873768E58822F87FE437D792028CB15929099EEE2F5DAE404CD39357591BA32E9AF4E162B8D3E7CB5EFE31CB20",
                    "nonce_indices": [
                        0,
                        2
                    ],
                    "key_indices": [
                        0,
                        2
                    ],
                    "tweak_indices": [],
                    "is_xonly": [],
                    "psig_indices": [
                        2,
                        3
                    ],
                    "expected": "1069B67EC3D2F3C7C08291ACCB17A9C9B8F2819A52EB5DF8726E17E7D6B52E9F01800260A7E9DAC450F4BE522DE4CE12BA91AEAF2B4279219EF74BE1D286ADD9"
                },
                {
                    "aggnonce": "0208C5C438C710F4F96A61E9FF3C37758814B8C3AE12BFEA0ED2C87FF6954FF186020B1816EA104B4FCA2D304D733E0E19CEAD51303FF6420BFD222335CAA402916D",
                    "nonce_indices": [
                        0,
                        3
                    ],
                    "key_indices": [
                        0,
                        2
                    ],
                    "tweak_indices": [
                        0
                    ],
                    "is_xonly": [
                        False
                    ],
                    "psig_indices": [
                        4,
                        5
                    ],
                    "expected": "5C558E1DCADE86DA0B2F02626A512E30A22CF5255CAEA7EE32C38E9A71A0E9148BA6C0E6EC7683B64220F0298696F1B878CD47B107B81F7188812D593971E0CC"
                },
                {
                    "aggnonce": "02B5AD07AFCD99B6D92CB433FBD2A28FDEB98EAE2EB09B6014EF0F8197CD58403302E8616910F9293CF692C49F351DB86B25E352901F0E237BAFDA11F1C1CEF29FFD",
                    "nonce_indices": [
                        0,
                        4
                    ],
                    "key_indices": [
                        0,
                        3
                    ],
                    "tweak_indices": [
                        0,
                        1,
                        2
                    ],
                    "is_xonly": [
                        True,
                        False,
                        True
                    ],
                    "psig_indices": [
                        6,
                        7
                    ],
                    "expected": "839B08820B681DBA8DAF4CC7B104E8F2638F9388F8D7A555DC17B6E6971D7426CE07BF6AB01F1DB50E4E33719295F4094572B79868E440FB3DEFD3FAC1DB589E"
                }
            ],
            "error_test_cases": [
                {
                    "aggnonce": "02B5AD07AFCD99B6D92CB433FBD2A28FDEB98EAE2EB09B6014EF0F8197CD58403302E8616910F9293CF692C49F351DB86B25E352901F0E237BAFDA11F1C1CEF29FFD",
                    "nonce_indices": [
                        0,
                        4
                    ],
                    "key_indices": [
                        0,
                        3
                    ],
                    "tweak_indices": [
                        0,
                        1,
                        2
                    ],
                    "is_xonly": [
                        True,
                        False,
                        True
                    ],
                    "psig_indices": [
                        7,
                        8
                    ],
                    "error": {
                        "type": "invalid_contribution",
                        "signer": 1
                    },
                    "comment": "Partial signature is invalid because it exceeds group size"
                }
            ]
        }
        msg = bytes.fromhex(test_data["msg"])
        for test in test_data["valid_test_cases"]:
            raw_pubkeys = [test_data["pubkeys"][i] for i in test["key_indices"]]
            pubkeys = [S256Point.parse(bytes.fromhex(raw)) for raw in raw_pubkeys]
            coor = MuSigCoordinator(pubkeys, sort=False)
            raw_tweaks = [test_data["tweaks"][i] for i in test["tweak_indices"]]
            tweaks = [Tweak(bytes.fromhex(raw), xonly) for raw, xonly in zip(raw_tweaks, test["is_xonly"])]
            for i, pnonce_index in enumerate(test["nonce_indices"]):
                raw = bytes.fromhex(test_data["pnonces"][pnonce_index])
                nonce_share = NoncePublicShare.parse(raw)
                coor.register_nonce_share(pubkeys[i].sec(), nonce_share)
            agg_nonce = coor.compute_nonce()
            self.assertEqual(agg_nonce.serialize(), bytes.fromhex(test["aggnonce"]))
            coor.create_signing_context(msg, tweaks)
            for i, psig_index in enumerate(test["psig_indices"]):
                raw = test_data["psigs"][psig_index]
                partial_s = bytes.fromhex(raw)
                coor.register_sig_share(pubkeys[i].sec(), partial_s)
            schnorr_signature = coor.compute_sig(msg)
            self.assertEqual(schnorr_signature.serialize().hex().upper(), test["expected"])
        for test in test_data["error_test_cases"]:
            raw_pubkeys = [test_data["pubkeys"][i] for i in test["key_indices"]]
            pubkeys = [S256Point.parse(bytes.fromhex(raw)) for raw in raw_pubkeys]
            coor = MuSigCoordinator(pubkeys, sort=False)
            raw_tweaks = [test_data["tweaks"][i] for i in test["tweak_indices"]]
            tweaks = [Tweak(bytes.fromhex(raw), xonly) for raw, xonly in zip(raw_tweaks, test["is_xonly"])]
            for i, pnonce_index in enumerate(test["nonce_indices"]):
                raw = bytes.fromhex(test_data["pnonces"][pnonce_index])
                nonce_share = NoncePublicShare.parse(raw)
                coor.register_nonce_share(pubkeys[i].sec(), nonce_share)
            agg_nonce = coor.compute_nonce()
            self.assertEqual(agg_nonce.serialize(), bytes.fromhex(test["aggnonce"]))
            coor.create_signing_context(msg, tweaks)
            with self.assertRaises(ValueError):
                for i, psig_index in enumerate(test["psig_indices"]):
                    raw = test_data["psigs"][psig_index]
                    partial_s = bytes.fromhex(raw)
                    coor.register_sig_share(pubkeys[i].sec(), partial_s)

    def test_sign_verify(self):
        test_data = {
            "sk": "7FB9E0E687ADA1EEBF7ECFE2F21E73EBDB51A7D450948DFE8D76D7F2D1007671",
            "pubkeys": [
                "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
                "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
                "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA661",
                "020000000000000000000000000000000000000000000000000000000000000007"
            ],
            "secnonces": [
                "508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F703935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
                "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9"
            ],
            "pnonces": [
                "0337C87821AFD50A8644D820A8F3E02E499C931865C2360FB43D0A0D20DAFE07EA0287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480",
                "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817980279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
                "032DE2662628C90B03F5E720284EB52FF7D71F4284F627B68A853D78C78E1FFE9303E4C5524E83FFE1493B9077CF1CA6BEB2090C93D930321071AD40B2F44E599046",
                "0237C87821AFD50A8644D820A8F3E02E499C931865C2360FB43D0A0D20DAFE07EA0387BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480",
                "0200000000000000000000000000000000000000000000000000000000000000090287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480"
            ],
            "aggnonces": [
                "028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9",
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "048465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9",
                "028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61020000000000000000000000000000000000000000000000000000000000000009",
                "028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD6102FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30"
            ],
            "msgs": [
                "F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF",
                "",
                "2626262626262626262626262626262626262626262626262626262626262626262626262626"
            ],
            "valid_test_cases": [
                {
                    "key_indices": [0, 1, 2],
                    "nonce_indices": [0, 1, 2],
                    "aggnonce_index": 0,
                    "msg_index": 0,
                    "signer_index": 0,
                    "expected": "012ABBCB52B3016AC03AD82395A1A415C48B93DEF78718E62A7A90052FE224FB"
                },
                {
                    "key_indices": [1, 0, 2],
                    "nonce_indices": [1, 0, 2],
                    "aggnonce_index": 0,
                    "msg_index": 0,
                    "signer_index": 1,
                    "expected": "9FF2F7AAA856150CC8819254218D3ADEEB0535269051897724F9DB3789513A52"
                },
                {
                    "key_indices": [1, 2, 0],
                    "nonce_indices": [1, 2, 0],
                    "aggnonce_index": 0,
                    "msg_index": 0,
                    "signer_index": 2,
                    "expected": "FA23C359F6FAC4E7796BB93BC9F0532A95468C539BA20FF86D7C76ED92227900"
                },
                # {
                #     "key_indices": [0, 1],
                #     "nonce_indices": [0, 3],
                #     "aggnonce_index": 1,
                #     "msg_index": 0,
                #     "signer_index": 0,
                #     "expected": "AE386064B26105404798F75DE2EB9AF5EDA5387B064B83D049CB7C5E08879531",
                #     "comment": "Both halves of aggregate nonce correspond to point at infinity"
                # },
                {
                    "key_indices": [0, 1, 2],
                    "nonce_indices": [0, 1, 2],
                    "aggnonce_index": 0,
                    "msg_index": 1,
                    "signer_index": 0,
                    "expected": "D7D63FFD644CCDA4E62BC2BC0B1D02DD32A1DC3030E155195810231D1037D82D",
                    "comment": "Empty message"
                },
                {
                    "key_indices": [0, 1, 2],
                    "nonce_indices": [0, 1, 2],
                    "aggnonce_index": 0,
                    "msg_index": 2,
                    "signer_index": 0,
                    "expected": "E184351828DA5094A97C79CABDAAA0BFB87608C32E8829A4DF5340A6F243B78C",
                    "comment": "38-byte message"
                }
            ],
            "sign_error_test_cases": [
                {
                    "key_indices": [1, 2],
                    "aggnonce_index": 0,
                    "msg_index": 0,
                    "secnonce_index": 0,
                    "error": {
                        "type": "value",
                        "message": "The signer's pubkey must be included in the list of pubkeys."
                    },
                    "comment": "The signers pubkey is not in the list of pubkeys. This test case is optional: it can be skipped by implementations that do not check that the signer's pubkey is included in the list of pubkeys."
                },
                {
                    "key_indices": [1, 0, 3],
                    "aggnonce_index": 0,
                    "msg_index": 0,
                    "secnonce_index": 0,
                    "error": {
                        "type": "invalid_contribution",
                        "signer": 2,
                        "contrib": "pubkey"
                    },
                    "comment": "Signer 2 provided an invalid public key"
                },
                {
                    "key_indices": [1, 2, 0],
                    "aggnonce_index": 2,
                    "msg_index": 0,
                    "secnonce_index": 0,
                    "error": {
                        "type": "invalid_contribution",
                        "signer": None,
                        "contrib": "aggnonce"
                    },
                    "comment": "Aggregate nonce is invalid due wrong tag, 0x04, in the first half"
                },
                {
                    "key_indices": [1, 2, 0],
                    "aggnonce_index": 3,
                    "msg_index": 0,
                    "secnonce_index": 0,
                    "error": {
                        "type": "invalid_contribution",
                        "signer": None,
                        "contrib": "aggnonce"
                    },
                    "comment": "Aggregate nonce is invalid because the second half does not correspond to an X coordinate"
                },
                {
                    "key_indices": [1, 2, 0],
                    "aggnonce_index": 4,
                    "msg_index": 0,
                    "secnonce_index": 0,
                    "error": {
                        "type": "invalid_contribution",
                        "signer": None,
                        "contrib": "aggnonce"
                    },
                    "comment": "Aggregate nonce is invalid because second half exceeds field size"
                },
                {
                    "key_indices": [0, 1, 2],
                    "aggnonce_index": 0,
                    "msg_index": 0,
                    "signer_index": 0,
                    "secnonce_index": 1,
                    "error": {
                        "type": "value",
                        "message": "first secnonce value is out of range."
                    },
                    "comment": "Secnonce is invalid which may indicate nonce reuse"
                }
            ],
            "verify_fail_test_cases": [
                {
                    "sig": "97AC833ADCB1AFA42EBF9E0725616F3C9A0D5B614F6FE283CEAAA37A8FFAF406",
                    "key_indices": [0, 1, 2],
                    "nonce_indices": [0, 1, 2],
                    "msg_index": 0,
                    "signer_index": 0,
                    "comment": "Wrong signature (which is equal to the negation of valid signature)"
                },
                {
                    "sig": "68537CC5234E505BD14061F8DA9E90C220A181855FD8BDB7F127BB12403B4D3B",
                    "key_indices": [0, 1, 2],
                    "nonce_indices": [0, 1, 2],
                    "msg_index": 0,
                    "signer_index": 1,
                    "comment": "Wrong signer"
                },
                {
                    "sig": "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
                    "key_indices": [0, 1, 2],
                    "nonce_indices": [0, 1, 2],
                    "msg_index": 0,
                    "signer_index": 0,
                    "comment": "Signature exceeds group size"
                }
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
                        "contrib": "pubnonce"
                    },
                    "comment": "Invalid pubnonce"
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
                        "contrib": "pubkey"
                    },
                    "comment": "Invalid pubkey"
                }
            ]
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
                aggnonce = test_data["aggnonces"][test["aggnonce_index"]]
                n1 = S256Point.parse(bytes.fromhex(aggnonce[:66]))
                n2 = S256Point.parse(bytes.fromhex(aggnonce[66:132]))
                coor = MuSigCoordinator(pubkeys, sort=False)
                raw_aggnonce = bytes.fromhex(test_data["aggnonces"][test["aggnonce_index"]])
                coor.agg_nonce = AggNonce.parse(raw_aggnonce)
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
                raw = test_data["pnonces"][pnonce_index]
                r1 = S256Point.parse(bytes.fromhex(raw[:66]))
                r2 = S256Point.parse(bytes.fromhex(raw[66:]))
                nonce_share = NoncePublicShare(r1, r2)
                coor.register_nonce_share(pubkeys[i].sec(), nonce_share)
            agg_nonce = coor.compute_nonce()
            self.assertEqual(agg_nonce.serialize(), bytes.fromhex(want_aggnonce))
            context = coor.create_signing_context(msg)
            sig_share = participant.sign(context)
            self.assertEqual(sig_share.hex().upper(), test["expected"])
            coor.register_sig_share(signer_pubkey.sec(), sig_share)
        cases = [*test_data["verify_fail_test_cases"], *test_data["verify_error_test_cases"]]
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
                sig_share = bytes.fromhex(test["sig"])
                coor.register_sig_share(signer_pubkey.sec(), sig_share)

    def test_tweak(self):
        test_data = {
            "sk": "7FB9E0E687ADA1EEBF7ECFE2F21E73EBDB51A7D450948DFE8D76D7F2D1007671",
            "pubkeys": [
                "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
                "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
                "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
            ],
            "secnonce": "508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F703935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
            "pnonces": [
                "0337C87821AFD50A8644D820A8F3E02E499C931865C2360FB43D0A0D20DAFE07EA0287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480",
                "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817980279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
                "032DE2662628C90B03F5E720284EB52FF7D71F4284F627B68A853D78C78E1FFE9303E4C5524E83FFE1493B9077CF1CA6BEB2090C93D930321071AD40B2F44E599046"
            ],
            "aggnonce": "028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9",
            "tweaks": [
                "E8F791FF9225A2AF0102AFFF4A9A723D9612A682A25EBE79802B263CDFCD83BB",
                "AE2EA797CC0FE72AC5B97B97F3C6957D7E4199A167A58EB08BCAFFDA70AC0455",
                "F52ECBC565B3D8BEA2DFD5B75A4F457E54369809322E4120831626F290FA87E0",
                "1969AD73CC177FA0B4FCED6DF1F7BF9907E665FDE9BA196A74FED0A3CF5AEF9D",
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
            ],
            "msg": "F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF",
            "valid_test_cases": [
                {
                    "key_indices": [1, 2, 0],
                    "nonce_indices": [1, 2, 0],
                    "tweak_indices": [0],
                    "is_xonly": [True],
                    "signer_index": 2,
                    "expected": "E28A5C66E61E178C2BA19DB77B6CF9F7E2F0F56C17918CD13135E60CC848FE91",
                    "comment": "A single x-only tweak"
                },
                {
                    "key_indices": [1, 2, 0],
                    "nonce_indices": [1, 2, 0],
                    "tweak_indices": [0],
                    "is_xonly": [False],
                    "signer_index": 2,
                    "expected": "38B0767798252F21BF5702C48028B095428320F73A4B14DB1E25DE58543D2D2D",
                    "comment": "A single plain tweak"
                },
                {
                    "key_indices": [1, 2, 0],
                    "nonce_indices": [1, 2, 0],
                    "tweak_indices": [0, 1],
                    "is_xonly": [False, True],
                    "signer_index": 2,
                    "expected": "408A0A21C4A0F5DACAF9646AD6EB6FECD7F7A11F03ED1F48DFFF2185BC2C2408",
                    "comment": "A plain tweak followed by an x-only tweak"
                },
                {
                    "key_indices": [1, 2, 0],
                    "nonce_indices": [1, 2, 0],
                    "tweak_indices": [0, 1, 2, 3],
                    "is_xonly": [False, False, True, True],
                    "signer_index": 2,
                    "expected": "45ABD206E61E3DF2EC9E264A6FEC8292141A633C28586388235541F9ADE75435",
                    "comment": "Four tweaks: plain, plain, x-only, x-only."
                },
                {
                    "key_indices": [1, 2, 0],
                    "nonce_indices": [1, 2, 0],
                    "tweak_indices": [0, 1, 2, 3],
                    "is_xonly": [True, False, True, False],
                    "signer_index": 2,
                    "expected": "B255FDCAC27B40C7CE7848E2D3B7BF5EA0ED756DA81565AC804CCCA3E1D5D239",
                    "comment": "Four tweaks: x-only, plain, x-only, plain. If an implementation prohibits applying plain tweaks after x-only tweaks, it can skip this test vector or return an error."
                }
            ],
            "error_test_cases": [
                {
                    "key_indices": [1, 2, 0],
                    "nonce_indices": [1, 2, 0],
                    "tweak_indices": [4],
                    "is_xonly": [False],
                    "signer_index": 2,
                    "error": {
                        "type": "value",
                        "message": "The tweak must be less than n."
                    },
                    "comment": "Tweak is invalid because it exceeds group size"
                }
            ]
        }
        secret = big_endian_to_int(bytes.fromhex(test_data["sk"]))
        private_key = PrivateKey(secret)
        k1 = big_endian_to_int(bytes.fromhex(test_data["secnonce"][:64]))
        k2 = big_endian_to_int(bytes.fromhex(test_data["secnonce"][64:128]))
        nonce_private_share = NoncePrivateShare(k1, k2, private_key.point)
        participant = MuSigParticipant(private_key, nonce_private_share)
        want_pubkey = S256Point.parse(bytes.fromhex(test_data["secnonce"][128:]))
        msg = bytes.fromhex(test_data["msg"])
        want_aggnonce = test_data["aggnonce"]
        for test in test_data["valid_test_cases"]:
            print(test)
            raw_pubkeys = [test_data["pubkeys"][i] for i in test["key_indices"]]
            pubkeys = [S256Point.parse(bytes.fromhex(raw)) for raw in raw_pubkeys]
            signer_pubkey = pubkeys[test["signer_index"]]
            self.assertEqual(signer_pubkey, want_pubkey)
            coor = MuSigCoordinator(pubkeys, sort=False)
            raw_tweaks = [test_data["tweaks"][i] for i in test["tweak_indices"]]
            tweaks = [Tweak(bytes.fromhex(raw), xonly) for raw, xonly in zip(raw_tweaks, test["is_xonly"])]
            for i, pnonce_index in enumerate(test["nonce_indices"]):
                raw = test_data["pnonces"][pnonce_index]
                r1 = S256Point.parse(bytes.fromhex(raw[:66]))
                r2 = S256Point.parse(bytes.fromhex(raw[66:]))
                nonce_share = NoncePublicShare(r1, r2)
                coor.register_nonce_share(pubkeys[i].sec(), nonce_share)
            agg_nonce = coor.compute_nonce()
            self.assertEqual(agg_nonce.serialize(), bytes.fromhex(want_aggnonce))
            context = coor.create_signing_context(msg, tweaks)
            sig_share = participant.sign(context)
            self.assertEqual(sig_share.hex().upper(), test["expected"])
            coor.register_sig_share(signer_pubkey.sec(), sig_share)
