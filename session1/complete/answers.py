"""
#code
>>> import ecc

#endcode
#markdown
# Schnorr Verification
* $eG=P$, $m$ message, $kG=R$, $H$ is a hash function
* Signature is $(R,s)$ where $s=k + e H(R||P||m)$
$$-H(R||P||m)P+sG$$
$$=-H(R||P||m)P+(k+e H(R||P||m))G$$
$$=-H(R||P||m)P+kG+H(R||P||m)(eG)$$
$$=R+H(R||P||m)P-H(R||P||m)P=R$$
#endmarkdown
#code
>>> from ecc import S256Point, SchnorrSignature, G, N
>>> from helper import big_endian_to_int
>>> from hash import sha256, hash_challenge
>>> msg = sha256(b"I attest to understanding Schnorr Signatures")
>>> sig_raw = bytes.fromhex("f3626c99fe36167e5fef6b95e5ed6e5687caa4dc828986a7de8f9423c0f77f9bc73091ed86085ce43de0e255b3d0afafc7eee41ddc9970c3dc8472acfcdfd39a")
>>> sig = SchnorrSignature.parse(sig_raw)
>>> xonly = bytes.fromhex("f01d6b9018ab421dd410404cb869072065522bf85734008f105cf385a023a80f")
>>> point = S256Point.parse(xonly)
>>> commitment = sig.r.xonly() + point.xonly() + msg
>>> challenge = big_endian_to_int(hash_challenge(commitment)) % N
>>> target = -challenge * point + sig.s * G
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
>>> # create the commitment: R || P || m (points should be xonly)
>>> commitment = sig.r.xonly() + p.xonly() + msg  #/
>>> # h is the hash_challenge of the commitment as a big endian int
>>> h = big_endian_to_int(hash_challenge(commitment))  #/
>>> # check that -hP+sG=R
>>> print(-h*p + sig.s*G  == sig.r)  #/
True

#endexercise
#unittest
ecc:SchnorrTest:test_verify:
#endunittest
#markdown
# Schnorr Signing
* $eG=P$, $m$ message, $k$ random
* $kG=R$, $H$ is <code>hash_challenge</code.
* $s=k+e H(R||P||m)$ where $R$ and $P$ are $x$-only
* Signature is $(R,s)$
#endmarkdown
#code
>>> # Example Signing
>>> from ecc import PrivateKey, N, G
>>> from hash import sha256, hash_challenge
>>> from helper import big_endian_to_int
>>> priv = PrivateKey(12345)
>>> e = priv.even_secret()
>>> msg = sha256(b"I attest to understanding Schnorr Signatures")
>>> k = 21016020145315867006318399104346325815084469783631925097217883979013588851039
>>> r = k * G
>>> if r.parity:
...     k = N - k
...     r = k * G
>>> commitment = r.xonly() + priv.point.xonly() + msg
>>> h = big_endian_to_int(hash_challenge(commitment)) % N
>>> s = (k + e * h) % N
>>> sig = SchnorrSignature(r, s)
>>> if not priv.point.verify_schnorr(msg, sig):
...     raise RuntimeError("Bad Signature")
>>> print(sig.serialize().hex())
f3626c99fe36167e5fef6b95e5ed6e5687caa4dc828986a7de8f9423c0f77f9bc73091ed86085ce43de0e255b3d0afafc7eee41ddc9970c3dc8472acfcdfd39a

#endcode
#exercise

Sign the message b"I'm learning Taproot!" with the private key 21,000,000

----

>>> from ecc import PrivateKey, N, G
>>> from hash import sha256, hash_challenge
>>> from helper import big_endian_to_int
>>> priv = PrivateKey(21000000)
>>> msg = sha256(b"I'm learning Taproot!")
>>> # We'll learn more about k later, for now use 987654321
>>> k = 987654321
>>> # get e using the even_secret method on the private key
>>> e = priv.even_secret() #/
>>> # calculate R which is kG
>>> r = k * G  #/
>>> # if R's y coordinate is odd (use the parity property), flip the k
>>> if r.parity:  #/
...     # set k to N - k
...     k = N - k  #/
...     # recalculate R
...     r = k * G  #/
>>> # calculate the commitment which is: R || P || msg
>>> commitment = r.xonly() + priv.point.xonly() + msg  #/
>>> # h is the hash_challenge of the commitment as a big endian integer mod N
>>> h = big_endian_to_int(hash_challenge(commitment)) % N  #/
>>> # calculate s which is (k+eh) mod N
>>> s = (k + e * h) % N  #/
>>> # create a SchnorrSignature object using the R and s
>>> schnorr = SchnorrSignature(r, s)  #/
>>> # check that this schnorr signature verifies
>>> if not priv.point.verify_schnorr(msg, schnorr):  #/
...     raise RuntimeError("Bad Signature")  #/
>>> # print the serialized hex of the signature
>>> print(schnorr.serialize().hex())  #/
5ad2703f5b4f4b9dea4c28fa30d86d3781d28e09dd51aae1208de80bb6155bee7d9dee36de5540efd633445a8d743816cbbc15fb8a1c7768984190d5b873a341

#endexercise
#unittest
ecc:SchnorrTest:test_sign:
#endunittest
#markdown
# $k$-generation
* Start with a number calle the auxillary
* Then xor auxillary with the secret
* Then hash the result with the message to make the $k$
* $k$ is unique to the secret and the message
* 32 0-bytes can be used to create a deterministic $k$
#endmarkdown
#code
>>> # Example Signing
>>> from ecc import PrivateKey, N
>>> from hash import sha256, hash_aux, hash_nonce
>>> from helper import big_endian_to_int, int_to_big_endian, xor_bytes
>>> aux = bytes([0] * 32)
>>> private_key = PrivateKey(21000000)
>>> e = priv.even_secret()
>>> msg = sha256(b"k-generation is cool!")
>>> # t contains the secret, msg is added so it's unique to the message and private key
>>> t = xor_bytes(int_to_big_endian(e, 32), hash_aux(aux))
>>> k = big_endian_to_int(hash_nonce(t + private_key.point.xonly())) % N
>>> print(k)
31125149427820969131614127332922859178956822599511456797208167813464334338237

#endcode
#exercise

Sign the message b"Deterministic k generation!" with the private key 837,120,557

----

>>> from ecc import PrivateKey, N, G
>>> from hash import sha256, hash_aux, hash_nonce
>>> from helper import big_endian_to_int, int_to_big_endian, xor_bytes
>>> priv = PrivateKey(21000000)
>>> msg = sha256(b"Deterministic k generation")
>>> # get e using the even_secret method on the private key
>>> e = priv.even_secret() #/
>>> # use the 32-bytes of 0's for the auxillary
>>> aux = bytes([0] * 32) #/
>>> # xor the even secret and the hash of the aux
>>> t = xor_bytes(int_to_big_endian(e, 32), hash_aux(aux)) #/
>>> # k is the hash_nonce of the result and the x-only pubkey as a big endian integer
>>> k = big_endian_to_int(hash_nonce(t + private_key.point.xonly())) % N #/
>>> # calculate R which is kG
>>> r = k * G  #/
>>> # if R's y coordinate is odd (use the parity property), flip the k
>>> if r.parity:  #/
...     # set k to N - k
...     k = N - k  #/
...     # recalculate R
...     r = k * G  #/
>>> # calculate the commitment which is: R || P || msg
>>> commitment = r.xonly() + priv.point.xonly() + msg  #/
>>> # h is the hash_challenge of the commitment as a big endian integer mod N
>>> h = big_endian_to_int(hash_challenge(commitment)) % N  #/
>>> # calculate s which is (k+eh) mod N
>>> s = (k + e * h) % N  #/
>>> # create a SchnorrSignature object using the R and s
>>> schnorr = SchnorrSignature(r, s)  #/
>>> # check that this schnorr signature verifies
>>> if not priv.point.verify_schnorr(msg, schnorr):  #/
...     raise RuntimeError("Bad Signature")  #/
>>> # print the serialized hex of the signature
>>> print(schnorr.serialize().hex())  #/
78133dcb92fd79c8928d4c3e498c41e431b137d418805e2455ecb39ff4da9b71f547d4bb87c6353e15b0b85837a515574533ab5f3e002dcf10448d475e848594

#endexercise
#unittest
ecc:SchnorrTest:test_bip340_k:
#endunittest
#markdown
# Batch Verification
* $e_iG=P_i$, $m_i$ message, $H$
* Signatures are $(R_i,s_i)$, $h_i=H(R_i||P_i||m_i)$
* $-h_1 P_1+s_1G=R_1$
* $-h_2 P_2+s_2G=R_2$
* $-h_1 P_1-h_2 P_2+(s_1+s_2)G=R_1+R_2$
* $(s_1+s_2)G=R_1+R_2+h_1 P_1+h_2 P_2$
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
>>> # h_i are the hash_challenge of the commitment as big endian ints mod N
>>> h1 = big_endian_to_int(hash_challenge(commitment_1)) % N  #/
>>> h2 = big_endian_to_int(hash_challenge(commitment_2)) % N  #/
>>> # h is the sum of the h_i P_i's
>>> h = h1*p1 + h2*p2  #/
>>> # check that sG=R+h
>>> print(s*G == r+h)  #/
True

#endexercise
#markdown
# Spending from the KeyPath
* $m$ is the Merkle Root $m$ of the ScriptPath
* Tweak $t$ and $P$ create $Q$, the external pubkey
* $t=H(P||m)$ where $H$ is <code>hash_taptweak</code>
* $Q=P+tG$, and $eG=P$ which means $Q=eG+tG$ and $Q=(e+t)G$
* $e+t$ is your private key, which can sign for the $Q$
* Witness has a single element, the Schnorr Signature
* If you don't want a script path, $m$ is the empty string
#endmarkdown
#code
>>> # Example Q calculation for a single-key
>>> from ecc import S256Point, G
>>> from hash import hash_taptweak
>>> from helper import big_endian_to_int
>>> from script import P2TRScriptPubKey
>>> internal_pubkey_raw = bytes.fromhex("cbaa648dbfe734646ce958e2f14a874149fae4010fdeabde4bae6a732537fd91")
>>> internal_pubkey = S256Point.parse(internal_pubkey_raw)
>>> t = big_endian_to_int(hash_taptweak(internal_pubkey_raw))
>>> external_pubkey = internal_pubkey + t * G
>>> script_pubkey = P2TRScriptPubKey(external_pubkey)
>>> print(script_pubkey)
OP_1 578444b411276eee17e2f69988d192b7e728f4375525a868f4a9c2b78e12af16

#endcode
#exercise

Make a P2TR ScriptPubKey using the private key 9284736473

----
>>> from ecc import PrivateKey, G
>>> from hash import hash_taptweak
>>> from helper import big_endian_to_int
>>> from script import P2TRScriptPubKey
>>> priv = PrivateKey(9284736473)
>>> # get the internal pubkey
>>> internal_pubkey = priv.point  #/
>>> # t is the hash_taptweak of the internal pubkey xonly as a big endian integer
>>> t = big_endian_to_int(hash_taptweak(internal_pubkey.xonly()))  #/
>>> # Q = P + tG
>>> external_pubkey = internal_pubkey + t * G  #/
>>> # use P2TRScriptPubKey to create the ScriptPubKey
>>> script_pubkey = P2TRScriptPubKey(external_pubkey)  #/
>>> # print the ScriptPubKey
>>> print(script_pubkey)  #/
OP_1 a6b9f4b7999f9c6de76165342c9feac354d5d3062a41761ed1616eaf9e3c38ec

#endexercise
#unittest
ecc:TapRootTest:test_default_tweak:
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
>>> internal_pubkey = S256Point.parse(internal_pubkey_raw)
>>> print(internal_pubkey.p2tr_address())
bc1p27zyfdq3yahwu9lz76vc35vjklnj3aph25j6s68548pt0rsj4utql46j72

>>> print(internal_pubkey.p2tr_address(network="signet"))
tb1p27zyfdq3yahwu9lz76vc35vjklnj3aph25j6s68548pt0rsj4utqgavay9

#endcode
#exercise

Make your own Signet P2TR Address

Submit your address at [this link]()

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
