"""
#code
>>> import ecc, hash

#endcode
#markdown
# Welcome!

Thank you for getting everything set up for the Programming Taproot Course. This Jupyter Notebook is a way for you to re-familiarize yourself with the system and practice solving problems. 

The two concepts that you'll learn here are tagged hashes and x-only pubkeys. These are new as part of the Taproot upgrade and a critical part of understanding Taproot, so please take the time to do all of the exercises.

#endmarkdown
#markdown
# Tagged Hashes - Motivation
* We want to use different hash functions so we don't get unnecessary Hash reuse
* We don't want to create a brand new hash functions, so we use sha256
* We use a different hash function for each context and we define each hash function like this.

#endmarkdown
#markdown
# Tagged Hashes - Implementation
* A Tagged Hash uses two rounds of SHA256
* The first round of SHA256 is a hash of a tag (e.g. "BIP0340/aux")
* The second round of SHA256 uses the resulting hash twice and also the message
* H_aux(x) = SHA256(SHA256("BIP0340/aux") + SHA256("BIP0340/aux") + x)

#endmarkdown
#code
>>> # Example Tagged Hashes
>>> from hash import sha256
>>> challenge_tag = b"BIP0340/challenge"
>>> msg = b"some message"
>>> challenge_hash = sha256(challenge_tag)
>>> hash_challenge = sha256(challenge_hash + challenge_hash + msg)
>>> print(hash_challenge.hex())
233a1e9353c5f782c96c1c08323fe9fca47ad161ee69d008846b68625c221113

#endcode
#exercise

What is the tagged hash "BIP0340/aux" of "hello world"?

----

>>> from hash import sha256
>>> # define the aux tag and the message as bytes (use b"")
>>> aux_tag = b"BIP0340/aux"  #/
>>> msg = b"hello world"  #/
>>> # calculate the aux tag hash using sha256
>>> aux_tag_hash = sha256(aux_tag)  #/
>>> # calculate the hash of the aux sha256 of (aux hash + aux hash + msg)
>>> hash_aux = sha256(aux_tag_hash + aux_tag_hash + msg)  #/
>>> # print the hash's hex
>>> print(hash_aux.hex())  #/
1d721a19d161e978e7436d9e73bb810a0a32cbdffc7a9b29e11713b1940a4126

#endexercise
#unittest
hash:HashTest:test_tagged_hash:
#endunittest
#markdown
# Tagged Hashes - Observations
* Each hash is different so that hashes cannot feasibly be re-used in different contexts
* There are 10 different contexts, each essentially having its own hash function
* The idea is that each tagged hash is different, though underneath, they all depend on the security of SHA256
#endmarkdown
#markdown
# $x$-only keys - Motivation
* Compressed SEC format is 33 bytes, we can Save 1 byte by using $x$-only keys
* As Schnorr Signatures define a point, we can reduce the size of of those from 72-73 bytes (DER-encoded ECDSA) to 64 bytes
* The ScriptPubKeys for pay-to-taproot also save a byte to be 34 bytes
#endmarkdown
#markdown
# $x$-only keys - Implementation
* To get down to 32-bytes, we simply assume that $y$ is even.
* This would be the same as the Compressed SEC format, but without the initial byte that lets us know whether the $y$ is even or odd.
* If the secret is $e$ and the point is $eG=P=(x,y)$ and the resulting $y$ is odd, here's what we do.
* The private key $e$ is flipped to $N-e$ if $y$ is odd
* $eG=P=(x,y)$ means $(N-e)G=0-eG=-P=(x,-y)$. Since we're in a finite field and the finite field prime $p$ is a prime number greater than 2, $-y=p-y$ is guaranteed to be even (odd minus odd)
#endmarkdown
#code
>>> # Example X-only pubkey
>>> from ecc import PrivateKey, S256Point
>>> from helper import int_to_big_endian
>>> pubkey = PrivateKey(12345).point
>>> xonly = int_to_big_endian(pubkey.x.num, 32)
>>> print(xonly.hex())
f01d6b9018ab421dd410404cb869072065522bf85734008f105cf385a023a80f

>>> pubkey2 = S256Point.parse(xonly)
>>> print(pubkey.x == pubkey2.x)
True

#endcode
#exercise
Find the $x$-only pubkey format for the private key with the secret 21,000,000

---
>>> from ecc import PrivateKey
>>> from helper import int_to_big_endian
>>> secret = 21000000
>>> # create a private key with the secret
>>> priv = PrivateKey(secret)  #/
>>> # get the public point for the private key
>>> point = priv.point  #/
>>> # convert the x coordinate to a big-endian integer 32 bytes
>>> xonly = int_to_big_endian(point.x.num, 32)  #/
>>> # print the hex of the xonly representation
>>> print(xonly.hex())  #/
e79c4eb45764bd015542f6779cc70fef44b7a2432f839264768288efab886291

#endexercise
#unittest
ecc:XOnlyTest:test_xonly:
#endunittest
#markdown
# $x$-only keys - Observations
* The savings for $x$-only keys is 1 byte for pubkeys, which trickles to a lot of other serializations (Schnorr Signatures, pay-to-taproot ScriptPubKeys, etc)
* However, there's now a bigger burden on the developer to "flip" the private key if the public key has an odd $y$
* This also ends up being challenging to account for, especially with respect to aggregated signatures and aggregated pubkeys.

Let's make a useful private-key flipping method in `PrivateKey`
#endmarkdown
#unittest
ecc:XOnlyTest:test_even_secret:
#endunittest
"""

FUNCTIONS = """
hash.tagged_hash
ecc.S256Point.xonly
ecc.S256Point.even_point
ecc.PrivateKey.even_secret
"""
