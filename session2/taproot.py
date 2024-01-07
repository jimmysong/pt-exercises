from io import BytesIO
from unittest import TestCase

from ecc import S256Point
from hash import (
    hash_tapbranch,
    hash_tapleaf,
)
from helper import int_to_byte
from op import encode_minimal_num, number_to_op_code
from script import ScriptPubKey
from timelock import Locktime, Sequence


def locktime_commands(locktime):
    assert isinstance(locktime, Locktime), f"{locktime} needs to be Locktime"
    # 0xB1 is OP_CLTV, 0x75 is OP_DROP
    return [encode_minimal_num(locktime), 0xB1, 0x75]


def sequence_commands(sequence):
    assert isinstance(sequence, Sequence), f"{sequence} needs to be Sequence"
    # 0xB2 is OP_CSV, 0x75 is OP_DROP
    return [encode_minimal_num(sequence), 0xB2, 0x75]


class TapLeaf:
    def __init__(self, tap_script, version=0xC0):
        self.tap_script = tap_script
        self.version = version

    def __repr__(self):
        return f"{self.version:x}:{self.tap_script}"

    def __eq__(self, other):
        return (
            type(self) is type(other)
            and self.version == other.version
            and self.tap_script == other.tap_script
        )

    def hash(self):
        # preimage is version in one byte and the tap script serialized
        # return the hash_tapleaf of the preimage
        raise NotImplementedError

    def path_hashes(self, leaf=None):
        return []

    def external_pubkey(self, internal_pubkey):
        return internal_pubkey.tweaked_key(self.hash())

    def control_block(self, internal_pubkey):
        """Assumes that this TapLeaf is the Merkle Root and constructs the
        control block"""
        external_pubkey = self.external_pubkey(internal_pubkey)
        if external_pubkey.even:
            parity = 0
        else:
            parity = 1
        return ControlBlock(
            self.version,
            parity,
            internal_pubkey,
            self.path_hashes(),
        )


class TapBranch:
    def __init__(self, left, right):
        for item in (left, right):
            if type(item) not in (TapBranch, TapLeaf):
                raise ValueError(
                    "TapBranch needs a TapBranch or TapLeaf as the left and right elements"
                )
            self.left = left
            self.right = right
            self._leaves = None

    def hash(self):
        # get the left and right hashes
        # use hash_tapbranch on them in alphabetical order
        raise NotImplementedError

    def leaves(self):
        if self._leaves is None:
            self._leaves = []
            self._leaves.extend(self.left.leaves())
            self._leaves.extend(self.right.leaves())
        return self._leaves

    def path_hashes(self, leaf):
        if leaf in self.left.leaves():
            return [*self.left.path_hashes(leaf), self.right.hash()]
        elif leaf in self.right.leaves():
            return [*self.right.path_hashes(leaf), self.left.hash()]
        else:
            return None

    def external_pubkey(self, internal_pubkey):
        return internal_pubkey.tweaked_key(self.hash())

    def control_block(self, internal_pubkey, leaf):
        """Assumes this TapBranch is the Merkle Root and returns the control
        block. Also requires the leaf to be one of the descendents"""
        if leaf not in self.leaves():
            return None
        external_pubkey = self.external_pubkey(internal_pubkey)
        if external_pubkey.even:
            parity = 0
        else:
            parity = 1
        return ControlBlock(
            leaf.version,
            parity,
            internal_pubkey,
            self.path_hashes(leaf),
        )

    @classmethod
    def make_root(cls, nodes):
        if len(nodes) == 1:
            return nodes[0]
        half_way = len(nodes) // 2
        left = cls.combine(nodes[:half_way])
        right = cls.combine(nodes[half_way:])
        return cls(left, right)


class ControlBlock:
    def __init__(self, version, parity, internal_pubkey, hashes):
        self.version = version
        self.parity = parity
        self.internal_pubkey = internal_pubkey
        self.hashes = hashes

    def __repr__(self):
        return f"{self.version}:{self.parity}:{self.internal_pubkey}"

    def __eq__(self, other):
        return self.serialize() == other.serialize()

    def merkle_root(self, tap_script):
        # create a TapLeaf from the tap_script and the tapleaf version in the control block
        # initialize the hash with the leaf's hash
        # go through the hashes in self.hashes
            # set the current hash as the hash_tapbranch of the sorted hashes
        # return the current hash
        raise NotImplementedError

    def external_pubkey(self, tap_script):
        # get the Merkle Root using self.merkle_root
        # return the external pubkey using the tweaked_key method of internal pubkey
        raise NotImplementedError

    def serialize(self):
        s = int_to_byte(self.version + self.parity)
        s += self.internal_pubkey.xonly()
        for h in self.hashes:
            s += h
        return s

    @classmethod
    def parse(cls, b):
        b_len = len(b)
        if b_len % 32 != 1:
            raise ValueError("There should be 32*m+1 bytes where m is an integer")
        if b_len < 33 or b_len > 33 + 128 * 32:
            raise ValueError(f"length is outside the bounds {b_len}")
        version = b[0] & 0xFE
        parity = b[0] & 1
        internal_pubkey = S256Point.parse_xonly(b[1:33])
        m = (b_len - 33) // 32
        hashes = [b[33 + 32 * i : 65 + 32 * i] for i in range(m)]
        return cls(version, parity, internal_pubkey, hashes)


class TapScript(ScriptPubKey):
    def tap_leaf(self):
        return TapLeaf(self)


class P2PKTapScript(TapScript):
    def __init__(self, point):
        super().__init__()
        if isinstance(point, S256Point):
            raw_point = point.xonly()
        elif isinstance(point, bytes):
            raw_point = point
        else:
            raise TypeError("To initialize P2PKTapScript, a point is needed")
        self.commands = [raw_point, 0xAC]


class MultiSigTapScript(TapScript):
    def __init__(self, points, k, locktime=None, sequence=None):
        if locktime is not None and sequence is not None:
            raise ValueError(
                "Both locktime and sequence are defined. Only one of them should be."
            )
        super().__init__()
        if len(points) == 0:
            raise ValueError("To initialize MultiSigTapScript at least one point")
        xonlys = sorted([p.xonly() for p in points])
        self.points = [S256Point.parse_xonly(b) for b in xonlys]
        if locktime is not None:
            self.commands = locktime_commands(locktime)
        elif sequence is not None:
            self.commands = sequence_commands(sequence)
        else:
            self.commands = []
        self.commands += [xonlys[0], 0xAC]
        if len(points) > 1:
            for xonly in xonlys[1:]:
                self.commands += [xonly, 0xBA]
            self.commands += [number_to_op_code(k), 0x87]


class TapRootTest(TestCase):
    def test_tapleaf_hash(self):
        tap_script = TapScript.parse(
            BytesIO(
                bytes.fromhex(
                    "4420331a8f6a14e1b41a6b523ddb505fbc0662a6446bd42408692497297d3474aeecad20158a49d62c384c539a453e41a70214cfb85184954ae5c8df4b47eb74d58ff16fac"
                )
            )
        )
        tap_leaf = TapLeaf(tap_script)
        self.assertEqual(
            tap_leaf.hash().hex(),
            "d1b3ee8e8c175e5db7e2ff7a87435e8f751d148b77fb1f00e14ff8ffa1c09a40",
        )

    def test_tapbranch_hash(self):
        pubkey_1 = S256Point.parse(
            bytes.fromhex(
                "331a8f6a14e1b41a6b523ddb505fbc0662a6446bd42408692497297d3474aeec"
            )
        ).xonly()
        pubkey_2 = S256Point.parse(
            bytes.fromhex(
                "158a49d62c384c539a453e41a70214cfb85184954ae5c8df4b47eb74d58ff16f"
            )
        ).xonly()
        tap_script_1 = TapScript([pubkey_1, 0xAC])
        tap_script_2 = TapScript([pubkey_2, 0xAC])
        tap_leaf_1 = TapLeaf(tap_script_1)
        tap_leaf_2 = TapLeaf(tap_script_2)
        tap_branch = TapBranch(tap_leaf_1, tap_leaf_2)
        self.assertEqual(
            tap_branch.hash().hex(),
            "eb792962b250f4a49a572ba7136674a28f2398a49c4c078fecfc839260da6151",
        )

    def test_control_block(self):
        raw_cb = bytes.fromhex(
            "c0407910a4cfa5fe195ad4844b6069489fcb429f27dff811c65e99f7d776e943e576f5c1cdfc8b07dc8edca5bef2b4991201c5a0e18b1dbbcfe00ef2295b8f6dff5dd270ec91aa5644d907059400edfd98e307a6f1c6fe3a2d1d4550674ff6bc6e"
        )
        cb = ControlBlock.parse(raw_cb)
        pubkey = bytes.fromhex(
            "027aa71d9cdb31cd8fe037a6f441e624fe478a2deece7affa840312b14e971a4"
        )
        tap_script = TapScript([pubkey, 0xAC])
        external_pubkey = cb.external_pubkey(tap_script)
        self.assertEqual(
            external_pubkey.xonly().hex(),
            "cbe433288ae1eede1f24818f08046d4e647fef808cfbbffc7d10f24a698eecfd",
        )

    def test_control_block_2(self):
        pubkey_1 = S256Point.parse(
            bytes.fromhex(
                "331a8f6a14e1b41a6b523ddb505fbc0662a6446bd42408692497297d3474aeec"
            )
        )
        pubkey_2 = S256Point.parse(
            bytes.fromhex(
                "158a49d62c384c539a453e41a70214cfb85184954ae5c8df4b47eb74d58ff16f"
            )
        )
        pubkey_3 = S256Point.parse(
            bytes.fromhex(
                "582662e8e47df59489d6756615aa3db3fa3bbaa75a424b9c78036265858f5544"
            )
        )
        tap_script_1 = TapScript([pubkey_1.xonly(), 0xAC])
        tap_script_2 = TapScript([pubkey_2.xonly(), 0xAC])
        tap_script_3 = TapScript([pubkey_3.xonly(), 0xAC])
        tap_leaf_1 = TapLeaf(tap_script_1)
        tap_leaf_2 = TapLeaf(tap_script_2)
        tap_leaf_3 = TapLeaf(tap_script_3)
        tap_branch_1 = TapBranch(tap_leaf_1, tap_leaf_2)
        tap_root = TapBranch(tap_branch_1, tap_leaf_3)
        hex_cb = "c0407910a4cfa5fe195ad4844b6069489fcb429f27dff811c65e99f7d776e943e576f5c1cdfc8b07dc8edca5bef2b4991201c5a0e18b1dbbcfe00ef2295b8f6dff5dd270ec91aa5644d907059400edfd98e307a6f1c6fe3a2d1d4550674ff6bc6e"
        internal_pubkey = S256Point.parse(
            bytes.fromhex(
                "407910a4cfa5fe195ad4844b6069489fcb429f27dff811c65e99f7d776e943e5"
            )
        )
        cb = tap_root.control_block(internal_pubkey, tap_leaf_2)
        self.assertEqual(cb.serialize().hex(), hex_cb)
