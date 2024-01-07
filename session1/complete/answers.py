"""
#code
>>> import ecc

#endcode
#markdown
# Schnorr Verification
* $e$ is the private key, $eG=P$, $z$ is the message, $k$ is the nonce, $kG=R$
* $\mathcal{H}$ is a tagged hash (BIP0340/challenge)
* $d$ challenge, $d=\mathcal{H}(R||P||z)$
* Signature is $(R,s)$ where $s=k + e d$
* Verify $R=sG-dP$
* $=(k+e d)G-dP =kG+d(eG)-dP=R+dP-dP=R$
#endmarkdown
#code
>>> from ecc import S256Point, SchnorrSignature, G, N
>>> from hash import hash_challenge
>>> from helper import big_endian_to_int
>>> msg = b"I'm learning Schnorr Signatures!"
>>> sig_raw = bytes.fromhex("3b5b656f623e314fcff97b44f93d4452992856e65fe0268a77a9a94c626eb1b11e8bcea138a15c185633fd66a7c1683843daa332c9d9e27a7178389d338521ab")
>>> sig = SchnorrSignature.parse(sig_raw)
>>> xonly = bytes.fromhex("a8a28557947025fe0646660677c09a757a3bce148d99fac9368439a13df6ea1a")
>>> p = S256Point.parse(xonly)
>>> commitment = sig.r.xonly() + p.xonly() + msg
>>> d = big_endian_to_int(hash_challenge(commitment))
>>> target = sig.s * G - d * p
>>> print(target == sig.r)
True

#endcode
#exercise

Verify this Schnorr Signature

Pubkey = cbaa648dbfe734646ce958e2f14a874149fae4010fdeabde4bae6a732537fd91
Signature = 2ae68f873376a0ff302258964632f7b98b21e3bbc72dcc8fb31de8acf01696b951f3dbb6fc5532558219472fb63e061f9a4c7d1760cc588da551c74374cd0de4
Message = 1a84547db188f0b1d2c9f0beac230afebbd5e6e6c1a46fc69841815194bf8612

---
>>> from ecc import SchnorrSignature, S256Point, N, G
>>> from hash import hash_challenge
>>> from helper import big_endian_to_int
>>> p_raw = bytes.fromhex("cbaa648dbfe734646ce958e2f14a874149fae4010fdeabde4bae6a732537fd91")
>>> p = S256Point.parse(p_raw)
>>> sig_raw = bytes.fromhex("2ae68f873376a0ff302258964632f7b98b21e3bbc72dcc8fb31de8acf01696b951f3dbb6fc5532558219472fb63e061f9a4c7d1760cc588da551c74374cd0de4")
>>> sig = SchnorrSignature.parse(sig_raw)
>>> msg = bytes.fromhex("1a84547db188f0b1d2c9f0beac230afebbd5e6e6c1a46fc69841815194bf8612")
>>> # create the commitment: R || P || z (points should be xonly)
>>> commitment = sig.r.xonly() + p.xonly() + msg  #/
>>> # d is the hash_challenge of the commitment as a big endian int
>>> d = big_endian_to_int(hash_challenge(commitment))  #/
>>> # check that R=sG-dP
>>> print(sig.r == sig.s*G - d*p)  #/
True

#endexercise
#unittest
ecc:SchnorrTest:test_verify:
#endunittest
#markdown
# Schnorr Signing
* $eG=P$, $m$ message, $k$ random
* $kG=R$, $H$ is <code>hash_challenge</code>.
* $s=k+e H(R||P||m)$ where $R$ and $P$ are $x$-only
* Signature is $(R,s)$
#endmarkdown
#code
# Example Signing
>>> from ecc import PrivateKey, N, G
>>> from hash import hash_challenge
>>> from helper import big_endian_to_int
>>> priv = PrivateKey(12345)
>>> e = priv.even_secret()
>>> msg = b"I'm learning Schnorr Signatures!"
>>> k = 21016020145315867006318399104346325815084469783631925097217883979013588851039
>>> r = k * G
>>> if not r.even:
...     k = N - k
...     r = k * G
>>> challenge = r.xonly() + priv.point.xonly() + msg
>>> d = big_endian_to_int(hash_challenge(challenge))
>>> s = (k + e * d) % N
>>> sig = SchnorrSignature(r, s)
>>> if not priv.point.verify_schnorr(msg, sig):
...     raise RuntimeError("Bad Signature")
>>> print(sig.serialize().hex())
f3626c99fe36167e5fef6b95e5ed6e5687caa4dc828986a7de8f9423c0f77f9bfc080c38ae75e45d7d3ba652d979b78d4b00520c834552653f7819af7b60ae71

#endcode
#exercise

Sign the message b"Schnorr Signatures adopt Taproot" with the private key 21,000,000

----

>>> from ecc import PrivateKey, N, G
>>> from hash import hash_challenge
>>> from helper import big_endian_to_int
>>> priv = PrivateKey(21000000)
>>> msg = b"Schnorr Signatures adopt Taproot"
>>> k = 987654321
>>> # get e using the even_secret method on the private key
>>> e = priv.even_secret()  #/
>>> # calculate the nonce point R which is kG
>>> r = k * G  #/
>>> # if R's not even, negate the k and recalculate R
>>> if not r.even:  #/
...     # set k to N - k
...     k = N - k  #/
...     # recalculate R
...     r = k * G  #/
>>> # calculate the commitment which is: R || P || msg
>>> commitment = r.xonly() + priv.point.xonly() + msg  #/
>>> # d is the hash_challenge of the commitment as a big endian integer
>>> d = big_endian_to_int(hash_challenge(commitment))  #/
>>> # calculate s = (k+ed) mod N
>>> s = (k + e * d) % N  #/
>>> # create a SchnorrSignature object using the R and s
>>> sig = SchnorrSignature(r, s)  #/
>>> # check that this schnorr signature verifies
>>> if not priv.point.verify_schnorr(msg, sig):  #/
...     raise RuntimeError("Bad Signature")  #/
>>> # print the serialized hex of the signature
>>> print(sig.serialize().hex())  #/
5ad2703f5b4f4b9dea4c28fa30d86d3781d28e09dd51aae1208de80bb6155bee012724e78be1a84fe7bbb14f3d8cbc6edd715e572b5b2c09e8838edfd53521db

#endexercise
#unittest
ecc:SchnorrTest:test_sign:
#endunittest
#markdown
# Nonce ($k$) Creation
* Start with a random number $a$, which is then hashed
* Xor the result $\mathcal{H_1}(a)$ with the secret $e$
* Then hash with the message $z$ to generate the $k$
* $P=eG$, $\mathcal{H_1}$ is <code>hash_aux</code>, $\mathcal{H_2}$ is <code>hash_nonce</code>
* $x = \mathcal{H_1}(a) \oplus e$, $k=\mathcal{H_2}(x||P||z)$
* $k$ is unique to both the secret and the message
* 32 0-bytes $a$ can be used to create a deterministic $k$
#endmarkdown
#code
>>> # example of nonce creation
>>> from ecc import PrivateKey, N
>>> from hash import sha256, hash_aux, hash_nonce
>>> from helper import big_endian_to_int, int_to_big_endian, xor_bytes
>>> aux = bytes([0] * 32)
>>> private_key = PrivateKey(21000000)
>>> p = private_key.point
>>> e = private_key.even_secret()
>>> msg = sha256(b"Nonce generation is spectacular!")
>>> x = xor_bytes(int_to_big_endian(e, 32), hash_aux(aux))
>>> k = big_endian_to_int(hash_nonce(x + p.xonly() + msg))
>>> print(hex(k))
0x862c62948caca77dc46ef04e3124c0542d838ae79172d5709a9edfb799c67e58

#endcode
#exercise

Sign the message b"Secure Deterministic Nonce made!" with the private key 837,120,557

----

>>> from ecc import PrivateKey, N, G
>>> from hash import sha256, hash_aux, hash_nonce
>>> from helper import big_endian_to_int, int_to_big_endian, xor_bytes
>>> priv = PrivateKey(21000000)
>>> point = priv.point
>>> msg = b"Secure Deterministic Nonce made!"
>>> # get e using the even_secret method on the private key
>>> e = priv.even_secret()  #/
>>> # use the 32-bytes of 0's for the auxillary
>>> a = bytes([0] * 32)  #/
>>> # x=e⊕H(a) where ⊕ is xor_bytes, H is hash_aux and a is the auxillary
>>> x = xor_bytes(int_to_big_endian(e, 32), hash_aux(a))  #/
>>> # k=H(x||P||z) where H is hash_nonce, P is the xonly of the point and z is the message
>>> k = big_endian_to_int(hash_nonce(x + point.xonly() + msg))  #/
>>> # calculate R which is kG
>>> r = k * G  #/
>>> # if R is not even negate the k
>>> if not r.even:  #/
...     # set k to N - k
...     k = N - k  #/
...     # recalculate R
...     r = k * G  #/
>>> # calculate the commitment which is: R || P || msg
>>> commitment = r.xonly() + point.xonly() + msg  #/
>>> # d is the hash_challenge of the commitment as a big endian integer
>>> d = big_endian_to_int(hash_challenge(commitment)) % N  #/
>>> # s=(k+ed) mod N
>>> s = (k + e * d) % N  #/
>>> # create a SchnorrSignature object using the R and s
>>> sig = SchnorrSignature(r, s)  #/
>>> # check that this schnorr signature verifies
>>> if not point.verify_schnorr(msg, sig):  #/
...     raise RuntimeError("Bad Signature")  #/
>>> # print the serialized hex of the signature
>>> print(sig.serialize().hex())  #/
3ea160fe0a9fcd6277ce5225e02fd17ae0778a62a684332740eb91c29c0f3a01b1cf2b2eaf18140861755e154d43e6385e7faeb4cf1fa8ff563886be68ff78f0

#endexercise
#unittest
ecc:SchnorrTest:test_bip340_k:
#endunittest
#markdown
# Batch Verification
* Pubkeys are $P_i$, Signatures are $(R_i,s_i)$
* Challenges are $d_i=\mathcal{H}(R_i||P_i||z_i)$
* $R_i=s_iG-d_iP_i$
* $\sum{R_i}=\sum{s_iG}-\sum{d_iP_i}$
* $(\sum{s_i})G=\sum{R_i}+\sum{d_iP_i}$
* Fewer total operations!
#endmarkdown
#exercise

Batch Verify these two Schnorr Signatures

Pubkey 1 = cbaa648dbfe734646ce958e2f14a874149fae4010fdeabde4bae6a732537fd91
Pubkey 2 = e79c4eb45764bd015542f6779cc70fef44b7a2432f839264768288efab886291

Signature 1 = 2ae68f873376a0ff302258964632f7b98b21e3bbc72dcc8fb31de8acf01696b951f3dbb6fc5532558219472fb63e061f9a4c7d1760cc588da551c74374cd0de4
Signature 2 = b6e52f38bc24f1420c4fdae8fa0f04b9b0374a12f18fd4699b06df53eb1386bfa88c1835cd19470cf8c76550eb549c988f9c8fac00cc56fadd4fcc3bf9d8800e

Message 1 = 1a84547db188f0b1d2c9f0beac230afebbd5e6e6c1a46fc69841815194bf8612
Message 2 = af1c325abcb0cced3a4166ce67be1db659ae1dd574fe49b0f2941d8d4882d62c

---
>>> from ecc import SchnorrSignature, S256Point, N, G
>>> from hash import hash_challenge
>>> from helper import big_endian_to_int
>>> p1_raw = bytes.fromhex("cbaa648dbfe734646ce958e2f14a874149fae4010fdeabde4bae6a732537fd91")
>>> p2_raw = bytes.fromhex("e79c4eb45764bd015542f6779cc70fef44b7a2432f839264768288efab886291")
>>> p1 = S256Point.parse(p1_raw)
>>> p2 = S256Point.parse(p2_raw)
>>> sig1_raw = bytes.fromhex("2ae68f873376a0ff302258964632f7b98b21e3bbc72dcc8fb31de8acf01696b951f3dbb6fc5532558219472fb63e061f9a4c7d1760cc588da551c74374cd0de4")
>>> sig2_raw = bytes.fromhex("b6e52f38bc24f1420c4fdae8fa0f04b9b0374a12f18fd4699b06df53eb1386bfa88c1835cd19470cf8c76550eb549c988f9c8fac00cc56fadd4fcc3bf9d8800e")
>>> sig1 = SchnorrSignature.parse(sig1_raw)
>>> sig2 = SchnorrSignature.parse(sig2_raw)
>>> msg1 = bytes.fromhex("1a84547db188f0b1d2c9f0beac230afebbd5e6e6c1a46fc69841815194bf8612")
>>> msg2 = bytes.fromhex("af1c325abcb0cced3a4166ce67be1db659ae1dd574fe49b0f2941d8d4882d62c")
>>> # define s as the s_i sum (make sure to mod by N)
>>> s = (sig1.s + sig2.s) % N  #/
>>> # define r as the signatures' r sum
>>> r = sig1.r + sig2.r  #/
>>> # create the commitments: R_i||P_i||m_i
>>> commitment_1 = sig1.r.xonly() + p1.xonly() + msg1  #/
>>> commitment_2 = sig2.r.xonly() + p2.xonly() + msg2  #/
>>> # d_i are the challenges which are hash_challenge of the commitments as big endian integers
>>> d1 = big_endian_to_int(hash_challenge(commitment_1)) % N  #/
>>> d2 = big_endian_to_int(hash_challenge(commitment_2)) % N  #/
>>> # d is the sum of the d_i P_i's
>>> d = d1*p1 + d2*p2  #/
>>> # check that sG=R+d
>>> print(s*G == r+d)  #/
True

#endexercise
#markdown
# Spending from the KeyPath
* $m$ is the Merkle Root of the ScriptPath
* Tweak $t$ and $P$ create $Q$, the external pubkey
* $t=\mathcal{H}(P||m)$ where $\mathcal{H}$ is <code>hash_taptweak</code>
* $Q=P+tG$, and $eG=P$ which means $Q=eG+tG$ and $Q=(e+t)G$
* $e+t$ is the private key for the public key $Q$
* Witness has a single element, the Schnorr Signature
* If you don't want a script path, $m$ is the empty string
#endmarkdown
#code
# Example UTXO creation for a p2tr with no script path
>>> from ecc import S256Point, G
>>> from hash import hash_taptweak
>>> from helper import big_endian_to_int
>>> from script import P2TRScriptPubKey
>>> internal_pubkey_raw = bytes.fromhex("cbaa648dbfe734646ce958e2f14a874149fae4010fdeabde4bae6a732537fd91")
>>> p = S256Point.parse(internal_pubkey_raw)
>>> m = b""
>>> t = big_endian_to_int(hash_taptweak(p.xonly() + m))
>>> q = p + t * G
>>> script_pubkey = P2TRScriptPubKey(q)
>>> print(script_pubkey)
OP_1 578444b411276eee17e2f69988d192b7e728f4375525a868f4a9c2b78e12af16

#endcode
#exercise

Make a P2TR ScriptPubKey with no Script Path using the private key 9284736473

----
>>> from ecc import PrivateKey, G
>>> from hash import hash_taptweak
>>> from helper import big_endian_to_int
>>> from script import P2TRScriptPubKey
>>> priv = PrivateKey(9284736473)
>>> # get the internal pubkey, P
>>> p = priv.point  #/
>>> # set the merkle root to the empty stning, m
>>> m = b""  #/
>>> # t is the hash_taptweak of the internal pubkey xonly and the merkle root as a big endian integer
>>> t = big_endian_to_int(hash_taptweak(p.xonly() + m))  #/
>>> # Q = P + tG
>>> q = p + t * G  #/
>>> # use P2TRScriptPubKey to create the ScriptPubKey
>>> script_pubkey = P2TRScriptPubKey(q)  #/
>>> # print the ScriptPubKey
>>> print(script_pubkey)  #/
OP_1 a6b9f4b7999f9c6de76165342c9feac354d5d3062a41761ed1616eaf9e3c38ec

#endexercise
#unittest
ecc:TapRootTest:test_tweak:
#endunittest
#unittest
ecc:TapRootTest:test_tweaked_key:
#endunittest
#unittest
ecc:TapRootTest:test_private_tweaked_key:
#endunittest
#unittest
ecc:TapRootTest:test_p2tr_script:
#endunittest
#markdown
# P2TR Addresses
* Segwit v0 uses Bech32
* Taproot (Segwit v1) uses Bech32m
* Bech32m is different than Bech32 (BIP350)
* Has error correcting capability and uses 32 letters/numbers
* Segwit v0 addresses start with <code>bc1q</code> and p2wpkh is shorter than p2wsh
* Segwit v1 addresses start with <code>bc1p</code> and they're all one length
#endmarkdown
#code
>>> # Example of getting a p2tr address
>>> from ecc import S256Point
>>> internal_pubkey_raw = bytes.fromhex("cbaa648dbfe734646ce958e2f14a874149fae4010fdeabde4bae6a732537fd91")
>>> p = S256Point.parse(internal_pubkey_raw)
>>> print(p.p2tr_address())
bc1p27zyfdq3yahwu9lz76vc35vjklnj3aph25j6s68548pt0rsj4utql46j72
>>> print(p.p2tr_address(network="signet"))
tb1p27zyfdq3yahwu9lz76vc35vjklnj3aph25j6s68548pt0rsj4utqgavay9

#endcode
#exercise

Make your own Signet P2TR Address

Submit your address at [this link](https://docs.google.com/spreadsheets/d/1BHqFAzgfThrf64q9pCinwTd7FitJrL5Is3HHBR3UyeI/edit?usp=sharing)

----
>>> from ecc import PrivateKey
>>> from hash import sha256
>>> from helper import big_endian_to_int
>>> my_email = b"jimmy@programmingblockchain.com"  #/my_email = b"<fill this in with your email>"
>>> my_secret = big_endian_to_int(sha256(my_email))
>>> # create the private key object
>>> priv = PrivateKey(my_secret)  #/
>>> # get the public point
>>> point = priv.point  #/
>>> # print the p2tr_address with network set to "signet"
>>> print(point.p2tr_address(network="signet"))  #/
tb1pfx2ys8pzcg0mdufk9v25hphv85zgjpv5kyn6uevdmfmvdsw0ea0qyvv87u

#endexercise
"""

FUNCTIONS = """
ecc.S256Point.verify_schnorr
ecc.PrivateKey.sign_schnorr
ecc.PrivateKey.bip340_k
ecc.S256Point.tweak
ecc.S256Point.tweaked_key
ecc.S256Point.p2tr_script
ecc.PrivateKey.tweaked_key
"""
