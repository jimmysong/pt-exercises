import hashlib

from unittest import TestCase


def sha256(x):
    return hashlib.sha256(x).digest()


def tagged_hash(tag, msg):
    # compute the sha256 of the tag using sha256
    tag_hash = sha256(tag)
    # compute the tagged hash by getting the sha256 of the tag hash + tag hash + message
    return sha256(tag_hash + tag_hash + msg)


def hash_aux(msg):
    return tagged_hash(b"BIP0340/aux", msg)


def hash_challenge(msg):
    # the tag for this hash is b"BIP0340/challenge"
    # return the result of the tagged_hash function
    return tagged_hash(b"BIP0340/challenge", msg)


def hash_keyaggcoef(msg):
    return tagged_hash(b"KeyAgg coefficient", msg)


def hash_keyagglist(msg):
    return tagged_hash(b"KeyAgg list", msg)


def hash_musignonce(msg):
    return tagged_hash(b"MuSig/noncecoef", msg)


def hash_nonce(msg):
    return tagged_hash(b"BIP0340/nonce", msg)


def hash_tapbranch(msg):
    return tagged_hash(b"TapBranch", msg)


def hash_tapleaf(msg):
    return tagged_hash(b"TapLeaf", msg)


def hash_tapsighash(msg):
    return tagged_hash(b"TapSighash", msg)


def hash_taptweak(msg):
    return tagged_hash(b"TapTweak", msg)


class HashTest(TestCase):
    def test_tagged_hash(self):
        want = "233a1e9353c5f782c96c1c08323fe9fca47ad161ee69d008846b68625c221113"
        self.assertEqual(hash_challenge(b"some message").hex(), want)
