"""
#code
>>> import ecc, musig

#endcode
#exercise

Now spend this output using the script path from the second TapLeaf send it all to <code>tb1q7kn55vf3mmd40gyj46r245lw87dc6us5n50lrg</code>

Use <a href="https://mempool.space/signet/tx/push to broadcast your transaction" target="_mempool">Mempool Signet</a> to broadcast your transaction

----
>>> from ecc import PrivateKey, S256Point
>>> from hash import sha256
>>> from helper import big_endian_to_int
>>> from script import address_to_script_pubkey
>>> from taproot import TapScript, TapLeaf, TapBranch
>>> from tx import Tx, TxIn, TxOut
>>> from witness import Witness
>>> my_email = b"jimmy@programmingblockchain.com"  #/my_email = b"<fill this in with your email>"
>>> my_secret = big_endian_to_int(sha256(my_email))
>>> my_private_key = PrivateKey(my_secret)
>>> internal_pubkey = S256Point.parse(bytes.fromhex("cd04c1bf88ca891af152fc57c36523ab59efb16b7ec07caca0cfc4a1f2051d9e"))
>>> pubkey_2 = bytes.fromhex("331a8f6a14e1b41a6b523ddb505fbc0662a6446bd42408692497297d3474aeec")
>>> pubkey_3 = bytes.fromhex("158a49d62c384c539a453e41a70214cfb85184954ae5c8df4b47eb74d58ff16f")
>>> my_xonly = my_private_key.point.xonly()
>>> tap_script_1 = TapScript([my_xonly, 0xAC])
>>> tap_leaf_1 = TapLeaf(tap_script_1)
>>> tap_script_2 = TapScript([pubkey_2, 0xAC])
>>> tap_leaf_2 = TapLeaf(tap_script_2)
>>> tap_script_3 = TapScript([pubkey_3, 0xAC])
>>> tap_leaf_3 = TapLeaf(tap_script_3)
>>> prev_tx = bytes.fromhex("201409034581136743bd7fd0a63f659d8142f1a41031d5a3c96bbe72135ab8a2")  #/prev_tx = bytes.fromhex("<fill this in with the tx you just submitted>")
>>> prev_index = 0
>>> target_address = "tb1q7kn55vf3mmd40gyj46r245lw87dc6us5n50lrg"
>>> fee = 500
>>> # create the two branches needed (leaf 1, leaf 2), (branch 1, leaf 3)
>>> tap_branch_1 = TapBranch(tap_leaf_1, tap_leaf_2)  #/
>>> tap_branch_2 = TapBranch(tap_branch_1, tap_leaf_3)  #/
>>> # create a transaction input
>>> tx_in = TxIn(prev_tx, prev_index)  #/
>>> # calculate the target amount
>>> target_amount = tx_in.value(network="signet") - fee  #/
>>> # calculate the target script
>>> target_script = address_to_script_pubkey(target_address)  #/
>>> # create a transaction output
>>> tx_out = TxOut(target_amount, target_script)  #/
>>> # create a transaction, segwit=True and network="signet"
>>> tx_obj = Tx(1, [tx_in], [tx_out], network="signet", segwit=True)  #/
>>> # create the control block from the TapBranch control_block method with internal_pubkey and tap_leaf_1
>>> cb = tap_branch_2.control_block(internal_pubkey, tap_leaf_1)
>>> # set the tx's witness to be the tap_script_1.raw_serialize() and control block, serialized
>>> tx_in.witness = Witness([tap_script_1.raw_serialize(), cb.serialize()])
>>> # set the message to be the transaction's sig_hash at index 0
>>> msg = tx_obj.sig_hash(0)
>>> # use sign_schnorr with yoru private key on the message and serialize it to get the signature
>>> sig = my_private_key.sign_schnorr(msg).serialize()
>>> # insert the sig in front of the other elements in the witness using tx_in.witness.items.insert
>>> tx_in.witness.items.insert(0, sig)
>>> # verify the transaction
>>> print(tx_obj.verify())
True
>>> # print the serialized hex
>>> print(tx_obj.serialize().hex())
01000000000101a2b85a1372be6bc9a3d53110a4f142819d653fa6d07fbd4367138145030914200000000000ffffffff0184e4000000000000160014f5a74a3131dedb57a092ae86aad3ee3f9b8d721403403b1681a67f40e6767b2db64744ad3f005d3971645135d58a3e1826d5c960bc281ce187bc9270c51ed7833fcf5e8415501862d51b0ebd051917d9878104778f292220cd04c1bf88ca891af152fc57c36523ab59efb16b7ec07caca0cfc4a1f2051d9eac61c0cd04c1bf88ca891af152fc57c36523ab59efb16b7ec07caca0cfc4a1f2051d9e76f5c1cdfc8b07dc8edca5bef2b4991201c5a0e18b1dbbcfe00ef2295b8f6dffaf5548715217f7a892c7c5ff787a97b6e2f123287a1a354fe3ccda09c39d5d7300000000

#endexercise
#markdown
# MuSig2 Key Aggregation
* Produce a Schnorr Signature $(R,s)$ from a group of $n$ public keys $P_1, P_2,..., P_n$ and present a single public key $P$ to satisfy $sG-\mathcal{H}(R,P,z)P=R$
* Each participant has its own secret $e_iG=P_i$
* We create a Group Commitment $L=\mathcal{H}(P_1||P_2||...||P_n)$
* Each Public Key gets its own coefficient: $\mathcal{H}(L,P_i)$
* The Group Public Key is $P=\mathcal{H}(L,P_1)P_1+\mathcal{H}(L,P_2)P_2+...+\mathcal{H}(L,P_n)P_n$
#endmarkdown
#code
>>> # creating a group public key
>>> from ecc import S256Point
>>> from hash import hash_keyagglist, hash_keyaggcoef
>>> from helper import big_endian_to_int
>>> raw_pubkeys = ["02ed3bace23c5e17652e174c835fb72bf53ee306b3406a26890221b4cef7500f88", "03cd5a3be41717d65683fe7a9de8ae5b4b8feced69f26a8b55eeefbcc2e74b75fb", "0385a7b790fc9d962493788317e4874a4ab07f1e9c78c773c47f2f6c96df756f05"]
>>> pubkeys = [S256Point.parse(bytes.fromhex(r)) for r in raw_pubkeys]
>>> preimage = b""
>>> for pubkey in pubkeys:
...     preimage += pubkey.sec()
>>> group_commitment = hash_keyagglist(preimage)
>>> terms = []
>>> for pubkey in pubkeys:
...     h = hash_keyaggcoef(group_commitment + pubkey.sec())
...     coef = big_endian_to_int(h)
...     terms.append(coef * pubkey)
>>> group_pubkey = S256Point.sum(terms)
>>> print(group_pubkey.sec().hex())
038c35af322902968e20f26417c36c314f82d933c031626901c98a693ad87245fa

#endcode
#exercise

Create a new group public key with these public keys:

* 034a5169f673aa632f538aaa128b6348536db2b637fd89073d49b6a23879cdb3ad
* 0225fa6a4190ddc87d9f9dd986726cafb901e15c21aafd2ed729efed1200c73de8
* 03ed214e8ce499d92a2085e7e6041b4f081c7d29d8770057fc705a131d2918fcdb
* 02609ae8d31e3b290e74483776c1c8dfc2756b87d9635d654eb9e1ca95c228b169
* 02ffe558e388852f0120e46af2d1b370f85854a8eb0841811ece0e3e03d282d57c
* 02d42d696f2c343dc67d80fcd85dbbdb2edef3cac71126625d0cbcacc231a00015

----
>>> from ecc import S256Point
>>> from hash import hash_keyagglist, hash_keyaggcoef
>>> from helper import big_endian_to_int
>>> raw_pubkeys = ["034a5169f673aa632f538aaa128b6348536db2b637fd89073d49b6a23879cdb3ad", "0225fa6a4190ddc87d9f9dd986726cafb901e15c21aafd2ed729efed1200c73de8", "03ed214e8ce499d92a2085e7e6041b4f081c7d29d8770057fc705a131d2918fcdb", "02609ae8d31e3b290e74483776c1c8dfc2756b87d9635d654eb9e1ca95c228b169", "02ffe558e388852f0120e46af2d1b370f85854a8eb0841811ece0e3e03d282d57c", "02d42d696f2c343dc67d80fcd85dbbdb2edef3cac71126625d0cbcacc231a00015"]
>>> # create the pubkeys using S256Point.parse
>>> pubkeys = [S256Point.parse(bytes.fromhex(s)) for s in raw_pubkeys]  #/
>>> # make the group commitment
>>> preimage = b""  #/
>>> # loop through the pubkeys
>>> for pubkey in pubkeys:  #/
...     preimage += pubkey.sec()  #/
>>> group_commitment = hash_keyagglist(preimage)  #/
>>> # create a list for the terms that will get summed
>>> terms = []  #/
>>> # loop through the pubkeys
>>> for pubkey in pubkeys:  #/
...     # calculate the hash of the group commitment and the sec
...     h = hash_keyaggcoef(group_commitment + pubkey.sec())  #/
...     # convert the hash to an integer
...     coef = big_endian_to_int(h)  #/
...     # add the coefficient * pubkey to the list of terms
...     terms.append(coef * pubkey)  #/
>>> # the group pubkey is the sum of the terms
>>> group_pubkey = S256Point.sum(terms)  #/
>>> # print the group pubkey's sec in hex
>>> print(group_pubkey.sec().hex())
03eb86d46031100b9814682e0052c6b7b9622dc66051f2cd2596fabf2789f31e1b

#endexercise
#markdown
# MuSig2 Key Aggregation in BIP342
* The coefficients would work fine, but there's one optimization made in BIP342
* Specifically, the second coefficient is always 1
* The reason that it's not the first is because of a corner case where all the public keys are the same
* There's also the fact that there's the possibility of the group point being an odd point when we're presenting the point in an x-only context(p2tr)
* The way this is solved is by every participant using the negated secret.
#endmarkdown
#code
>>> # creating a group public key in BIP342
>>> from ecc import S256Point
>>> from hash import hash_keyagglist, hash_keyaggcoef
>>> from helper import big_endian_to_int
>>> raw_pubkeys = ["02ed3bace23c5e17652e174c835fb72bf53ee306b3406a26890221b4cef7500f88", "03cd5a3be41717d65683fe7a9de8ae5b4b8feced69f26a8b55eeefbcc2e74b75fb", "0385a7b790fc9d962493788317e4874a4ab07f1e9c78c773c47f2f6c96df756f05"]
>>> pubkeys = [S256Point.parse(bytes.fromhex(r)) for r in raw_pubkeys]
>>> preimage = b""
>>> for pubkey in pubkeys:
...     preimage += pubkey.sec()
>>> group_commitment = hash_keyagglist(preimage)
>>> terms = []
>>> second_point = None
>>> for pubkey in pubkeys:
...     if pubkey != pubkeys[0] and second_point is None:
...         second_point = pubkey
...     if pubkey == second_point:
...         coef = 1
...     else:
...         h = hash_keyaggcoef(group_commitment + pubkey.sec())
...         coef = big_endian_to_int(h)
...     terms.append(coef * pubkey)
>>> group_pubkey = S256Point.sum(terms)
>>> print(group_pubkey.sec().hex())
023f0b11ae77cef9dbf91181b858306a662265bd648a4c2c4016d55e3815c3985a

#endcode
#exercise

Create a new group public key according to BIP342 with these public keys:

* 034a5169f673aa632f538aaa128b6348536db2b637fd89073d49b6a23879cdb3ad
* 0225fa6a4190ddc87d9f9dd986726cafb901e15c21aafd2ed729efed1200c73de8
* 03ed214e8ce499d92a2085e7e6041b4f081c7d29d8770057fc705a131d2918fcdb
* 02609ae8d31e3b290e74483776c1c8dfc2756b87d9635d654eb9e1ca95c228b169
* 02ffe558e388852f0120e46af2d1b370f85854a8eb0841811ece0e3e03d282d57c
* 02d42d696f2c343dc67d80fcd85dbbdb2edef3cac71126625d0cbcacc231a00015

----
>>> from ecc import S256Point
>>> from hash import hash_keyagglist, hash_keyaggcoef
>>> from helper import big_endian_to_int
>>> raw_pubkeys = ["034a5169f673aa632f538aaa128b6348536db2b637fd89073d49b6a23879cdb3ad", "0225fa6a4190ddc87d9f9dd986726cafb901e15c21aafd2ed729efed1200c73de8", "03ed214e8ce499d92a2085e7e6041b4f081c7d29d8770057fc705a131d2918fcdb", "02609ae8d31e3b290e74483776c1c8dfc2756b87d9635d654eb9e1ca95c228b169", "02ffe558e388852f0120e46af2d1b370f85854a8eb0841811ece0e3e03d282d57c", "02d42d696f2c343dc67d80fcd85dbbdb2edef3cac71126625d0cbcacc231a00015"]
>>> # create the pubkeys using S256Point.parse
>>> pubkeys = [S256Point.parse(bytes.fromhex(s)) for s in raw_pubkeys]  #/
>>> # make the group commitment
>>> preimage = b""  #/
>>> # loop through the pubkeys
>>> for pubkey in pubkeys:  #/
...     preimage += pubkey.sec()  #/
>>> group_commitment = hash_keyagglist(preimage)  #/
>>> # create a list for the terms that will get summed
>>> terms = []  #/
>>> # initialize the second poinnt with None
>>> second_point = None  #/
>>> # loop through the pubkeysa
>>> for pubkey in pubkeys:  #/
...     # if the second point is None and the pubkey is not the first one
...     if second_point is None and pubkey != pubkeys[0]:  #/
...         # then designate the second point to be this pubkey
...         second_point = pubkey  #/
...     # if the current pubkey is the second point, coef is 1
...     if pubkey == second_point:  #/
...         coef = 1  #/
...     # otherwise
...     else:  #/
...         # calculate the hash of the group commitment and the sec
...         h = hash_keyaggcoef(group_commitment + pubkey.sec())  #/
...         # convert the hash to an integer
...         coef = big_endian_to_int(h)  #/
...     # add the coefficient * pubkey to the list of terms
...     terms.append(coef * pubkey)  #/
>>> # the group pubkey is the sum of the terms
>>> group_pubkey = S256Point.sum(terms)  #/
>>> # print the group pubkey's sec in hex
>>> print(group_pubkey.sec().hex())
03628b3911ec6818290dbc40e0039652ceac6bef4355c6b461af870d0aafa123a0

#endexercise
#unittest
musig:KeyAggTest:test_compute_group_commitment
#endunittest
#unittest
musig:KeyAggTest:test_compute_group_point
#endunittest
#exercise

Create a new group public key according to BIP342 with your neighbor.

----
>>> from ecc import S256Point
>>> from musig import KeyAggregator
>>> # insert your and someone else's sec pubkeys here
>>> raw_pubkeys = ["03cd04c1bf88ca891af152fc57c36523ab59efb16b7ec07caca0cfc4a1f2051d9e", "03334104808fc821c1ba4e933d6ecce6d1f409ce324889cdc0131c03d0e9840a8c"]  #/raw_pubkeys = ["<my pubkey in compressed sec>", "<my neighbor's pubkey in compressed sec>"]
>>> # create the pubkeys using S256Point.parse
>>> pubkeys = [S256Point.parse(bytes.fromhex(s)) for s in raw_pubkeys]  #/
>>> # create the keyaggcontext
>>> keyagg = KeyAggregator(pubkeys)  #/
>>> # now print the group point's sec in hex
>>> print(keyagg.group_point.sec().hex())  #/
031d087fbb722f28e82ad0560ec0223253c2c63fee1bd057692b167bb689fa1dbb

#endexercise
#markdown
# MuSig2 Nonce Creation
* Every participant creates a private nonce share (numbers $l_i$ and $m_i$) and communicates the nonce share points to the coordinator ($l_i * G=S_i, m_i * G=T_i$)
* When the nonce share points are gathered, the coordinator communicates nonce point sums to each participant. $S = S_1+S_2+...+S_n, T=T_1+T_2+...+T_n$ along with the message being signed and the key aggregation data.
* The nonce coefficient is $b = \mathcal{H}(S || T || P || z)$ where $P$ is the group point and $z$ is the message being signed
* The nonce point for the signature $R = S + b * T$
* The same nonce coefficient ($b$) can now be used to determine each participant's nonce ($k$) $k_i = l_i + b * m_i$
#endmarkdown
#example
>>> # Example nonce generation
>>> from ecc import N, PrivateKey
>>> from hash import hash_musignoncecoef
>>> from musig import KeyAggregator, MuSigParticipant, MuSigCoordinator
>>> msg = b"MuSig2 is awesome!"
>>> participants = [MuSigParticipant(PrivateKey(i * 1000)) for i in range(1, 7)]
>>> pubkeys = [p.point for p in participants]
>>> coor = MuSigCoordinator(pubkeys)
>>> for p in participants:
...     nonce_share = p.generate_nonce_share(rand=b'')
...     coor.register_nonce_share(p.point.sec(), nonce_share)
>>> group_point = coor.keyagg.group_point
>>> s = S256Point.sum([n.s for n in coor.nonce_shares.values()])
>>> t = S256Point.sum([n.t for n in coor.nonce_shares.values()])
>>> h = hash_musignoncecoef(s.sec()+t.sec()+group_point.xonly()+msg)
>>> nonce_coef = big_endian_to_int(h)
>>> nonce_point = s + nonce_coef*t
>>> print(nonce_point.sec().hex())
038f12dde9f661cdd1d655a6fa8ac600de344550a1d70f1c0f5376e2600fa94a6b
>>> k = (participants[0].private_share.l + nonce_coef * participants[0].private_share.m) % N
>>> print(hex(k))
0xb17767a513f759bda07c356a8292cb41d05ca7aaecdaeb6d3067be2d4386a5df

#endexample
#exercise

Calculate the k for participant 1:

Participant 1's secret: 1000
Participant 2's secret: 2000

message: b"Hello World!"

Participant 1's $l$ and $m$: 3000, 4000
Participant 2's $l$ and $m$: 5000, 6000

----
>>> from ecc import N, PrivateKey
>>> from hash import hash_musignoncecoef
>>> from helper import big_endian_to_int
>>> from musig import KeyAggregator, NoncePrivateShare, MuSigParticipant, MuSigCoordinator
>>> participant_1 = MuSigParticipant(PrivateKey(1000))
>>> participant_2 = MuSigParticipant(PrivateKey(2000))
>>> msg = b"Hello World!"
>>> nonce_share_1 = NoncePrivateShare(3000, 4000, participant_1.point)
>>> nonce_share_2 = NoncePrivateShare(5000, 6000, participant_2.point)
>>> pubkeys = [participant_1.point, participant_2.point]
>>> coor = MuSigCoordinator(pubkeys)
>>> coor.register_nonce_share(participant_1.point.sec(), nonce_share_1.public_share)
>>> coor.register_nonce_share(participant_2.point.sec(), nonce_share_2.public_share)
>>> # grab the group point from coordinator's keyagg property's group_point
>>> group_point = coor.keyagg.group_point  #/
>>> # calculate s and t by summing the s and t properties from the nonce_shares.values()
>>> s = S256Point.sum([n.s for n in coor.nonce_shares.values()])  #/
>>> t = S256Point.sum([n.t for n in coor.nonce_shares.values()])  #/
>>> # calculate the hash of s's sec, t's sec, the group point's xonly and the message
>>> h = hash_musignoncecoef(s.sec() + t.sec() + group_point.xonly() + msg)  #/
>>> # the nonce coefficient is the hash interpreted as a big endian integer
>>> nonce_coef = big_endian_to_int(h)  #/
>>> # the nonce point is S+bT
>>> nonce_point = s + nonce_coef*t  #/
>>> # print the nonce point's sec in hex
>>> print(nonce_point.sec().hex())  #/
0254d698964537d2f322797ef5f38307516789b22f27da7d5e6855447ea2b50aff
>>> # k=l+bm (l and m are properties of nonce_share_1) make sure to mod by N
>>> k = (nonce_share_1.l + nonce_coef * nonce_share_1.m) % N  #/
>>> # print the hex of k
>>> print(hex(k))
0xab2527543594209be30a92c94a01754bdf1a10b7ca2084b2b188f712c73e66a0

#endexercise
#unittest
musig:NonceAggTest:test_compute_nonce_point
#endunittest
"""

FUNCTIONS = """
musig.KeyAggregator.compute_group_commitment
musig.KeyAggregator.keyagg_coef
musig.KeyAggregator.compute_group_point
musig.MuSigCoordinator.compute_nonce_point
"""
