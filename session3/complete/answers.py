"""
#code
>>> import ecc, musig

#endcode
#code
>>> # Example ScriptPath Spend
>>> from ecc import PrivateKey, S256Point
>>> from hash import sha256
>>> from script import address_to_script_pubkey
>>> from taproot import TapScript, TapLeaf, TapBranch
>>> from tx import Tx, TxIn, TxOut
>>> from witness import Witness
>>> my_secret = 21000000
>>> my_private_key = PrivateKey(my_secret)
>>> p = S256Point.parse(bytes.fromhex("cd04c1bf88ca891af152fc57c36523ab59efb16b7ec07caca0cfc4a1f2051d9e"))
>>> pubkey_2 = bytes.fromhex("331a8f6a14e1b41a6b523ddb505fbc0662a6446bd42408692497297d3474aeec")
>>> pubkey_3 = bytes.fromhex("158a49d62c384c539a453e41a70214cfb85184954ae5c8df4b47eb74d58ff16f")
>>> my_xonly = my_private_key.point.xonly()
>>> tap_script_1 = TapScript([my_xonly, 0xAC])
>>> tap_leaf_1 = TapLeaf(tap_script_1)
>>> tap_script_2 = TapScript([pubkey_2, 0xAC])
>>> tap_leaf_2 = TapLeaf(tap_script_2)
>>> tap_script_3 = TapScript([pubkey_3, 0xAC])
>>> tap_leaf_3 = TapLeaf(tap_script_3)
>>> prev_tx = bytes.fromhex("42251c52fa8c6a6a349eee1729ced9587483ea6d6e210d6c42bb640d33a4da25")
>>> prev_index = 0
>>> target_address = "tb1pxh7kypwsvxnat0z6588pufhx43r2fnqjyn846qj5kx8mgqcamvjsyn5cjg"
>>> fee = 500
>>> tap_branch_1 = TapBranch(tap_leaf_1, tap_leaf_2)
>>> tap_branch_2 = TapBranch(tap_branch_1, tap_leaf_3)
>>> tx_in = TxIn(prev_tx, prev_index)
>>> target_amount = tx_in.value(network="signet") - fee
>>> target_script = address_to_script_pubkey(target_address)
>>> tx_out = TxOut(target_amount, target_script)
>>> tx_obj = Tx(1, [tx_in], [tx_out], network="signet", segwit=True)
>>> cb = tap_branch_2.control_block(p, tap_leaf_1)
>>> tx_in.witness = Witness([tap_script_1.raw_serialize(), cb.serialize()])
>>> msg = tx_obj.sig_hash(0)
>>> sig = my_private_key.sign_schnorr(msg).serialize()
>>> tx_in.witness.items.insert(0, sig)
>>> tx_obj.verify()
True
>>> print(tx_obj.serialize().hex())
0100000000010125daa4330d64bb426c0d216e6dea837458d9ce2917ee9e346a6a8cfa521c25420000000000ffffffff01ac8401000000000022512035fd6205d061a7d5bc5aa1ce1e26e6ac46a4cc1224cf5d0254b18fb4031ddb250340de0d3823e951b010fd079e34310b38a65228b28d6daa3deca73651e602ee96c53af2a23a2a147ff211f03df97a92c83606596d99eba8a74b2a04e14618cb95b92220e79c4eb45764bd015542f6779cc70fef44b7a2432f839264768288efab886291ac61c0cd04c1bf88ca891af152fc57c36523ab59efb16b7ec07caca0cfc4a1f2051d9e76f5c1cdfc8b07dc8edca5bef2b4991201c5a0e18b1dbbcfe00ef2295b8f6dffaf5548715217f7a892c7c5ff787a97b6e2f123287a1a354fe3ccda09c39d5d7300000000

#endcode
#exercise

You have been sent 100,000 sats to the address you created in the last exercise of the last session. Use the TapScript with your pubkey to spend all of it and send everything minus the fee to <code>tb1q7kn55vf3mmd40gyj46r245lw87dc6us5n50lrg</code>. Use <a href="https://mempool.space/signet/tx/push to broadcast your transaction" target="_mempool">Mempool Signet</a> to broadcast your transaction.

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
>>> p = S256Point.parse(bytes.fromhex("cd04c1bf88ca891af152fc57c36523ab59efb16b7ec07caca0cfc4a1f2051d9e"))
>>> pubkey_2 = bytes.fromhex("331a8f6a14e1b41a6b523ddb505fbc0662a6446bd42408692497297d3474aeec")
>>> pubkey_3 = bytes.fromhex("158a49d62c384c539a453e41a70214cfb85184954ae5c8df4b47eb74d58ff16f")
>>> my_xonly = my_private_key.point.xonly()
>>> tap_script_1 = TapScript([my_xonly, 0xAC])
>>> tap_leaf_1 = TapLeaf(tap_script_1)
>>> tap_script_2 = TapScript([pubkey_2, 0xAC])
>>> tap_leaf_2 = TapLeaf(tap_script_2)
>>> tap_script_3 = TapScript([pubkey_3, 0xAC])
>>> tap_leaf_3 = TapLeaf(tap_script_3)
>>> prev_tx = bytes.fromhex("201409034581136743bd7fd0a63f659d8142f1a41031d5a3c96bbe72135ab8a2")  #/prev_tx = bytes.fromhex("<fill this in with the tx hash of a UTXO that belongs to you>")
>>> # fill in the following with the correct output index from the UTXO
>>> prev_index = 0  #/prev_index = -1
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
>>> cb = tap_branch_2.control_block(p, tap_leaf_1)  #/
>>> # set the tx_in's witness to be the tap_script_1.raw_serialize() and control block, serialized
>>> tx_in.witness = Witness([tap_script_1.raw_serialize(), cb.serialize()])  #/
>>> # set the message to be the transaction's sig_hash at index 0
>>> msg = tx_obj.sig_hash(0)  #/
>>> # use sign_schnorr with yoru private key on the message and serialize it to get the signature
>>> sig = my_private_key.sign_schnorr(msg).serialize()  #/
>>> # insert the sig in front of the other elements in the witness using tx_in.witness.items.insert
>>> tx_in.witness.items.insert(0, sig)  #/
>>> # verify the transaction
>>> print(tx_obj.verify())  #/
True
>>> # print the serialized hex
>>> print(tx_obj.serialize().hex())  #/
01000000000101a2b85a1372be6bc9a3d53110a4f142819d653fa6d07fbd4367138145030914200000000000ffffffff0184e4000000000000160014f5a74a3131dedb57a092ae86aad3ee3f9b8d721403403b1681a67f40e6767b2db64744ad3f005d3971645135d58a3e1826d5c960bc281ce187bc9270c51ed7833fcf5e8415501862d51b0ebd051917d9878104778f292220cd04c1bf88ca891af152fc57c36523ab59efb16b7ec07caca0cfc4a1f2051d9eac61c0cd04c1bf88ca891af152fc57c36523ab59efb16b7ec07caca0cfc4a1f2051d9e76f5c1cdfc8b07dc8edca5bef2b4991201c5a0e18b1dbbcfe00ef2295b8f6dffaf5548715217f7a892c7c5ff787a97b6e2f123287a1a354fe3ccda09c39d5d7300000000

#endexercise
#markdown
# MuSig2 Key Aggregation
* Produce a Schnorr Signature $(R,s)$ from a group of $n$ public keys $P_1, P_2,..., P_n$ and present a single public key $P$ to satisfy $sG-\mathcal{H}(R,P,z)P=R$
* Each participant has its own secret $e_iG=P_i$
* We create a Group Commitment $L=\mathcal{H}(P_1||P_2||...||P_n)$
* Each Public Key gets its own keyagg coefficient: $\mathcal{H}(L,P_i)$
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
>>> for p_i in pubkeys:
...     h = hash_keyaggcoef(group_commitment + p_i.sec())
...     c_i = big_endian_to_int(h)
...     terms.append(c_i * p_i)
>>> p = S256Point.sum(terms)
>>> print(p.sec().hex())
038c35af322902968e20f26417c36c314f82d933c031626901c98a693ad87245fa

#endcode
#exercise

Create a new group public key with these component public keys:

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
>>> # create the pubkeys using S256Point.parse and bytes.fromhex()
>>> pubkeys = [S256Point.parse(bytes.fromhex(s)) for s in raw_pubkeys]  #/
>>> # The preimage for the group commitment is L=H(P_1||P_2||...||P_n) in sec format
>>> preimage = b""  #/
>>> # loop through the pubkeys
>>> for pubkey in pubkeys:  #/
...     # add the sec for this key to the preimage
...     preimage += pubkey.sec()  #/
>>> # create the commitment hash by doing hash_keyagglist on the preimage
>>> group_commitment = hash_keyagglist(preimage)  #/
>>> # create a list for the terms that will get summed
>>> terms = []  #/
>>> # loop through the pubkeys
>>> for p_i in pubkeys:  #/
...     # calculate the hash of the group commitment and the sec usig hash_keyaggcoef
...     h = hash_keyaggcoef(group_commitment + p_i.sec())  #/
...     # convert the hash to an integer
...     c_i = big_endian_to_int(h)  #/
...     # add the coefficient * pubkey to the list of terms
...     terms.append(c_i * p_i)  #/
>>> # the group pubkey is the S256Point.sum of the terms
>>> p = S256Point.sum(terms)  #/
>>> # print the group pubkey's sec in hex
>>> print(p.sec().hex())  #/
03eb86d46031100b9814682e0052c6b7b9622dc66051f2cd2596fabf2789f31e1b

#endexercise
#markdown
# BIP327 Key Aggregation
* The coefficients would work fine, but there's one optimization made in BIP327
* Specifically, the second coefficient is always 1, all other coefficients stay the same
* The reason that it's not the first is because of a corner case where all the public keys are the same
* There's also the fact that there's the possibility of the group point being odd
* The way this is solved is by every participant negating their secret
#endmarkdown
#code
>>> # creating a BIP327 group public key
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
>>> for p_i in pubkeys:
...     if p_i != pubkeys[0] and second_point is None:
...         second_point = p_i
...     if p_i == second_point:
...         c_i = 1
...     else:
...         h = hash_keyaggcoef(group_commitment + p_i.sec())
...         c_i = big_endian_to_int(h)
...     terms.append(c_i * p_i)
>>> p = S256Point.sum(terms)
>>> print(p.sec().hex())
023f0b11ae77cef9dbf91181b858306a662265bd648a4c2c4016d55e3815c3985a

#endcode
#exercise

Create a BIP327 group public key with these public keys:

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
>>> # create the pubkeys using S256Point.parse and bytes.fromhex()
>>> pubkeys = [S256Point.parse(bytes.fromhex(s)) for s in raw_pubkeys]  #/
>>> # The preimage for the group commitment is L=H(P_1||P_2||...||P_n) in sec format
>>> preimage = b""  #/
>>> # loop through the pubkeys
>>> for pubkey in pubkeys:  #/
...     # add the sec for this key to the preimage
...     preimage += pubkey.sec()  #/
>>> # create the commitment hash by doing hash_keyagglist on the preimage
>>> group_commitment = hash_keyagglist(preimage)  #/
>>> # create a list for the terms that will get summed
>>> terms = []  #/
>>> # initialize the second point with None
>>> second_point = None  #/
>>> # loop through the pubkeys
>>> for p_i in pubkeys:  #/
...     # if the second point is None and the pubkey is not the first one
...     if second_point is None and p_i != pubkeys[0]:  #/
...         # then designate the second point to be this pubkey
...         second_point = p_i  #/
...     # if the current pubkey is the second point, coefficient is 1
...     if p_i == second_point:  #/
...         c_i = 1  #/
...     # otherwise
...     else:  #/
...         # calculate the hash_keyaggcoef of the group commitment and the sec
...         h = hash_keyaggcoef(group_commitment + p_i.sec())  #/
...         # convert the hash to an integer
...         c_i = big_endian_to_int(h)  #/
...     # add the coefficient * pubkey to the list of terms
...     terms.append(c_i * p_i)  #/
>>> # the group pubkey is the S256Point.sum of the terms
>>> p = S256Point.sum(terms)  #/
>>> # print the group pubkey's sec in hex
>>> print(p.sec().hex())  #/
03628b3911ec6818290dbc40e0039652ceac6bef4355c6b461af870d0aafa123a0

#endexercise
#unittest
musig:KeyAggTest:test_compute_group_point:
#endunittest
#exercise

Create a 2-of-2 BIP327 public key sharing a key with your neighbor.

----
>>> from ecc import PrivateKey, S256Point
>>> from helper import big_endian_to_int, sha256
>>> from musig import KeyAggregator
>>> my_email = b"jimmy@programmingblockchain.com"  #/my_email = b"<fill this in with your email>"
>>> my_secret = big_endian_to_int(sha256(my_email))
>>> my_pubkey = PrivateKey(my_secret).point
>>> # print your pubkey in sec format
>>> print(my_private_key.point.sec().hex())  #/
03cd04c1bf88ca891af152fc57c36523ab59efb16b7ec07caca0cfc4a1f2051d9e
>>> # get your neighbor's sec pubkey
>>> neighbor_pubkey = S256Point.parse(bytes.fromhex("03334104808fc821c1ba4e933d6ecce6d1f409ce324889cdc0131c03d0e9840a8c"))  #/neighbor_pubkey = S256Point.parse(bytes.fromhex("<your neighbor's sec pubkey>"))
>>> # create the keyaggcontext
>>> keyagg = KeyAggregator([my_pubkey, neighbor_pubkey])  #/
>>> # now print the group point's sec in hex
>>> print(keyagg.group_point.sec().hex())  #/
03aa07c1b044d6a3ce168d5b41475026e21420b188f2065d87fdec25925be2f139

#endexercise
#markdown
# MuSig2 Nonce Creation
* Every participant creates a private nonce share (numbers $l_i$ and $m_i$) and communicates the nonce share points to the coordinator ($l_i * G=S_i, m_i * G=T_i$)
* When the nonce share points are gathered, the coordinator communicates nonce point sums to each participant. $S = S_1+S_2+...+S_n, T=T_1+T_2+...+T_n$ along with the message being signed and the key aggregation data.
* The nonce coefficient is $b = \mathcal{H}(S || T || P || z)$ where $P$ is the group point and $z$ is the message being signed
* The nonce point for the signature $R = S + b * T$
* The same nonce coefficient ($b$) can now be used to determine each participant's nonce ($k$) $k_i = l_i + b * m_i$
#endmarkdown
#code
>>> # Example nonce generation
>>> from ecc import N, PrivateKey
>>> from hash import hash_musignoncecoef
>>> from musig import KeyAggregator, MuSigParticipant, MuSigCoordinator
>>> msg = b"MuSig2 is awesome!"
>>> participants = [MuSigParticipant(PrivateKey(i * 1000)) for i in range(1, 7)]
>>> pubkeys = [p.point for p in participants]
>>> coor = MuSigCoordinator(pubkeys)
>>> for p in participants:
...     nonce_share = p.generate_nonce_share(msg=msg, rand=b'')
...     coor.register_nonce_share(p.point.sec(), nonce_share)
>>> group_point = coor.keyagg.group_point
>>> s = S256Point.sum([n.s for n in coor.nonce_shares.values()])
>>> t = S256Point.sum([n.t for n in coor.nonce_shares.values()])
>>> h = hash_musignoncecoef(s.sec()+t.sec()+group_point.xonly()+msg)
>>> b = big_endian_to_int(h)
>>> r = s + b*t
>>> print(r.sec().hex())
036096fad5844253ea42accc3141abcfab7505d1c88421ded7a47534b090eeb192
>>> k = (participants[0].nonce_private_share.l + b * participants[0].nonce_private_share.m) % N
>>> print(hex(k))
0x649739191173454a10dd1c3856d6df54488504c3cc33422aeded22ae0713b07c

#endcode
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
>>> z = b"Hello World!"
>>> nonce_share_1 = NoncePrivateShare(3000, 4000, participant_1.point)
>>> nonce_share_2 = NoncePrivateShare(5000, 6000, participant_2.point)
>>> pubkeys = [participant_1.point, participant_2.point]
>>> coor = MuSigCoordinator(pubkeys)
>>> coor.register_nonce_share(participant_1.point.sec(), nonce_share_1.public_share)
>>> coor.register_nonce_share(participant_2.point.sec(), nonce_share_2.public_share)
>>> # grab the group point, p, from coordinator's group_point
>>> p = coor.group_point  #/
>>> # calculate s and t by summing the s and t properties from the nonce_shares.values()
>>> s = S256Point.sum([n.s for n in coor.nonce_shares.values()])  #/
>>> t = S256Point.sum([n.t for n in coor.nonce_shares.values()])  #/
>>> # calculate the hash_musignoncecoef of s's sec, t's sec, p's xonly and the message, z
>>> h = hash_musignoncecoef(s.sec() + t.sec() + p.xonly() + z)  #/
>>> # the nonce coefficient, b, is the hash interpreted as a big endian integer
>>> b = big_endian_to_int(h)  #/
>>> # the r=S+bT
>>> r = s + b*t  #/
>>> # print the nonce point's sec in hex
>>> print(r.sec().hex())  #/
0254d698964537d2f322797ef5f38307516789b22f27da7d5e6855447ea2b50aff
>>> # k=l+bm (l and m are properties of nonce_share_1) make sure to mod by N
>>> k = (nonce_share_1.l + b * nonce_share_1.m) % N  #/
>>> # print the hex of k
>>> print(hex(k))  #/
0xab2527543594209be30a92c94a01754bdf1a10b7ca2084b2b188f712c73e66a0

#endexercise
#unittest
musig:NonceAggTest:test_compute_nonce_point:
#endunittest
#exercise

Create a nonce point and nonce coefficient with your neighbor for this message: b"Love thy neighbor"

----
>>> from ecc import N, PrivateKey
>>> from hash import hash_musignoncecoef
>>> from helper import big_endian_to_int, sha256
>>> from musig import NoncePrivateShare, NoncePublicShare, MuSigParticipant, MuSigCoordinator
>>> msg = b"Love thy neighbor"
>>> my_secret = big_endian_to_int(sha256(b"jimmy@programmingblockchain.com"))  #/my_secret = big_endian_to_int(sha256(b"<my email address>"))
>>> me = MuSigParticipant(PrivateKey(my_secret))
>>> my_pubkey = me.point
>>> neighbor_pubkey = S256Point.parse(bytes.fromhex("02e79c4eb45764bd015542f6779cc70fef44b7a2432f839264768288efab886291"))  #/neighbor_pubkey = S256Point.parse(bytes.fromhex("<my neighbor's sec pubkey>"))
>>> # create the coordinator with me and my neighbor
>>> coor = MuSigCoordinator([my_pubkey, neighbor_pubkey])  #/
>>> # generate my nonce share using generate_nonce_share
>>> my_nonce_share = me.generate_nonce_share(msg=msg, rand=b'')  #/
>>> # print the nonce share's serialization in hex and share with your neighbor
>>> print(my_nonce_share.serialize().hex())  #/
03d2b367270076e3cf7f7b3eb03231fea9ba0143b702fd14b196c36b7e7edc8213021e336acb6087523fe8b2f5c5d25fa8debfa4427af16e490c3020e9dff89970bf
>>> neighbor_share = NoncePublicShare.parse(bytes.fromhex("03d2b367270076e3cf7f7b3eb03231fea9ba0143b702fd14b196c36b7e7edc8213021e336acb6087523fe8b2f5c5d25fa8debfa4427af16e490c3020e9dff89970bf"))  #/neighbor_share = NoncePublicShare.parse(bytes.fromhex("<fill in with your neighbor's hex public nonce share>"))
>>> # register my nonce share to the coordinator
>>> coor.register_nonce_share(my_pubkey.sec(), my_nonce_share)  #/
>>> # register neighbor's share to the coordinator
>>> coor.register_nonce_share(neighbor_pubkey.sec(), neighbor_share)  #/
>>> # compute the nonce point from the coordinator
>>> r = coor.compute_nonce_point(msg)  #/
>>> # print the sec format in hex of the nonce point
>>> print(r.sec().hex())  #/
0267e93ad9188b248db67b5dbbdca5755633fd32a4e90cbdb2b1a1dcd23135853a

#endexercise
#markdown
# MuSig2 Partial Signatures
* Every participant calculates $k_i=l_i+b m_i$ using the nonce coefficient $b= \mathcal{H}(S||T||P||z)$
* They also need the keyagg coefficient $c_i = \mathcal{H}(L || P_i)$ and the challenge $d=\mathcal{H}(R,P,z)$ where $z$ is the message)
* The partial signature can then be calculated $s_i = k_i + c_i * d * e_i$ where $e_i$ is the secret
* The sum of the partial signatures is the s part of the Schnorr Signature $s=s_1+s_2+...+s_n$
* If $R$ is odd, we use $-k_i$ for the signing. Similarly, if $P$ is odd, we use $-e_i$ for signing
#endmarkdown
#code
>>> from ecc import N, PrivateKey
>>> from musig import SigningContext, MuSigParticipant, MuSigCoordinator
>>> participant_1 = MuSigParticipant(PrivateKey(1000))
>>> participant_2 = MuSigParticipant(PrivateKey(2000))
>>> msg = b"MuSig2 is awesome!"
>>> nonce_share_1 = participant_1.generate_nonce_share(msg=msg, rand=b'')
>>> nonce_share_2 = participant_2.generate_nonce_share(msg=msg, rand=b'')
>>> pubkeys = [participant_1.point, participant_2.point]
>>> coor = MuSigCoordinator(pubkeys)
>>> coor.register_nonce_share(participant_1.point.sec(), nonce_share_1)
>>> coor.register_nonce_share(participant_2.point.sec(), nonce_share_2)
>>> context = coor.create_signing_context(msg)
>>> if context.nonce_point.even:
...     k = participant_1.nonce(context.nonce_coef)
... else:
...     k = N - participant_1.nonce(context.nonce_coef)
>>> if context.group_point.even:
...     e = participant_1.private_key.secret
... else:
...     e = N - participant_1.private_key.secret
>>> c = context.keyagg_coef(participant_1.point)
>>> d = context.challenge
>>> s = (k + c * d * e) % N
>>> print(hex(s))
0xa5aa0ae6ba94c1d8948929b7422d14869476011f4a5904c8f46b276396d4051a

#endcode
#markdown
# MuSig2 Partial Signature Verification
* To verify a partial signature, we need some data from the coordinator: group commitment, message being signed, aggregate nonce point and aggregate pubkey
* We also need the participant nonce point and pubkey.
* $c_i$ is the aggregate key coefficient $\mathcal{H}(L||P_i)$ and $d$ is group commitment $\mathcal{H}(R||P||z)$
* $s_i=k_i+c_i d e_i$ so what we check is $s_i G=k_iG+c_i d e_i G=R_i+c_i d P_i$ or $R=s_i G-c_i d P_i$
#endmarkdown
#code
>>> # example of verifying a partial signature
>>> from ecc import G, N, PrivateKey
>>> from musig import SigningContext, MuSigParticipant, MuSigCoordinator
>>> participant_1 = MuSigParticipant(PrivateKey(1000))
>>> participant_2 = MuSigParticipant(PrivateKey(2000))
>>> msg = b"MuSig2 is awesome!"
>>> nonce_share_1 = participant_1.generate_nonce_share(msg=msg, rand=b'')
>>> nonce_share_2 = participant_2.generate_nonce_share(msg=msg, rand=b'')
>>> pubkeys = [participant_1.point, participant_2.point]
>>> coor = MuSigCoordinator(pubkeys)
>>> coor.register_nonce_share(participant_1.point.sec(), nonce_share_1)
>>> coor.register_nonce_share(participant_2.point.sec(), nonce_share_2)
>>> context = coor.create_signing_context(msg)
>>> s = 0xa5aa0ae6ba94c1d8948929b7422d14869476011f4a5904c8f46b276396d4051a
>>> if context.nonce_point.even:
...     r = nonce_share_1.nonce_point(context.nonce_coef)
... else:
...     r = -1 * nonce_share_1.nonce_point(context.nonce_coef)
>>> if context.group_point.even:
...     p = participant_1.point
... else:
...     p = -1 * participant_1.point
>>> c = context.keyagg_coef(participant_1.point)
>>> d = context.challenge
>>> print(s * G == r + c * d * p)
True

#endcode
#exercise

Calculate the partial signature for participant 2:

Participant 1's secret: 1000
Participant 2's secret: 2000

message: b"Hello World!"

Participant 1's $l$ and $m$: 3000, 4000
Participant 2's $l$ and $m$: 5000, 6000

----
>>> from ecc import N, PrivateKey
>>> from musig import SigningContext, MuSigParticipant, MuSigCoordinator
>>> participant_1 = MuSigParticipant(PrivateKey(1000))
>>> participant_2 = MuSigParticipant(PrivateKey(2000))
>>> msg = b"Hello World!"
>>> nonce_share_1 = NoncePrivateShare(3000, 4000, participant_1.point)
>>> nonce_share_2 = NoncePrivateShare(5000, 6000, participant_2.point)
>>> participant_1.nonce_private_share = nonce_share_1
>>> participant_2.nonce_private_share = nonce_share_2
>>> pubkeys = [participant_1.point, participant_2.point]
>>> coor = MuSigCoordinator(pubkeys)
>>> coor.register_nonce_share(participant_1.point.sec(), nonce_share_1.public_share)
>>> coor.register_nonce_share(participant_2.point.sec(), nonce_share_2.public_share)
>>> # create the signing context, which should aggregate the points
>>> context = coor.create_signing_context(msg)  #/
>>> # determine the second participant's nonce (k_i) from the nonce point's evenness
>>> if context.nonce_point.even:  #/
...     k = participant_2.nonce(context.nonce_coef)  #/
... else:  #/
...     k = N - participant_2.nonce(context.nonce_coef)  #/
>>> # determine the second participant's secret (e_i) from the group point's evenness
>>> if context.group_point.even:  #/
...     e = participant_2.private_key.secret  #/
... else:  #/
...     e = N - participant_2.private_key.secret  #/
>>> # use the context's keylagg_coef method to get the keyagg coefficient (c_i = H(L||P_i))
>>> c = context.keyagg_coef(participant_2.point)  #/
>>> # use the context's challenge method to get the group challenge (d = H(R||P||z))
>>> d = context.challenge  #/
>>> # now get the partial signature s_i = k + c_i * d * e_i
>>> s = (k + c * d * e) % N  #/
>>> # print the hex of the partial signature
>>> print(hex(s))  #/
0x9d4815237aa9e06f5ae095bef95898c584f835c9df0389ad46e1f94c8034b621

#endexercise
#exercise

Verify the partial signature for participant 2

----
>>> from ecc import G, N, PrivateKey
>>> from musig import SigningContext, MuSigParticipant, MuSigCoordinator
>>> participant_1 = MuSigParticipant(PrivateKey(1000))
>>> participant_2 = MuSigParticipant(PrivateKey(2000))
>>> msg = b"Hello World!"
>>> nonce_share_1 = NoncePrivateShare(3000, 4000, participant_1.point)
>>> nonce_share_2 = NoncePrivateShare(5000, 6000, participant_2.point)
>>> participant_1.nonce_private_share = nonce_share_1
>>> participant_2.nonce_private_share = nonce_share_2
>>> pubkeys = [participant_1.point, participant_2.point]
>>> coor = MuSigCoordinator(pubkeys)
>>> coor.register_nonce_share(participant_1.point.sec(), nonce_share_1.public_share)
>>> coor.register_nonce_share(participant_2.point.sec(), nonce_share_2.public_share)
>>> # fill in what s equals from the last exercise
>>> s = 0x9d4815237aa9e06f5ae095bef95898c584f835c9df0389ad46e1f94c8034b621  #/
>>> # create the signing context, which should aggregate the points
>>> context = coor.create_signing_context(msg)  #/
>>> # determine the second participant's nonce point (R_i) from the nonce point's evenness
>>> if context.nonce_point.even:  #/
...     r = nonce_share_2.public_share.nonce_point(context.nonce_coef)  #/
... else:  #/
...     r = -1 * nonce_share_2.public_share.nonce_point(context.nonce_coef)  #/
>>> # determine the second participant's pubkey (P_i) from the group point's evenness
>>> if context.group_point.even:  #/
...     p = participant_2.point  #/
... else:  #/
...     p = -1 * participant_2.point  #/
>>> # get the keyagg coefficient (c) for the second participant
>>> c = context.keyagg_coef(participant_2.point)  #/
>>> # get the challenge for the group (d)
>>> d = context.challenge  #/
>>> # check if s_i * G == R + c * d * P
>>> print(s * G == r + c * d * p)  #/
True

#endexercise
#exercise

Sum the partial signatures, create a Schnorr Signature and verify it using the group point

----
>>> from ecc import G, N, PrivateKey, SchnorrSignature
>>> from musig import SigningContext, MuSigParticipant, MuSigCoordinator
>>> participant_1 = MuSigParticipant(PrivateKey(1000))
>>> participant_2 = MuSigParticipant(PrivateKey(2000))
>>> msg = b"Hello World!"
>>> nonce_share_1 = NoncePrivateShare(3000, 4000, participant_1.point)
>>> nonce_share_2 = NoncePrivateShare(5000, 6000, participant_2.point)
>>> participant_1.nonce_private_share = nonce_share_1
>>> participant_2.nonce_private_share = nonce_share_2
>>> pubkeys = [participant_1.point, participant_2.point]
>>> coor = MuSigCoordinator(pubkeys)
>>> coor.register_nonce_share(participant_1.point.sec(), nonce_share_1.public_share)
>>> coor.register_nonce_share(participant_2.point.sec(), nonce_share_2.public_share)
>>> context = coor.create_signing_context(msg)
>>> s_1 = 0x1aad95d9490e4b8599377ff6a546a1d075fb4242c749dbcbc010589e23c21776
>>> s_2 = 0x9d4815237aa9e06f5ae095bef95898c584f835c9df0389ad46e1f94c8034b621
>>> # sum the two partial sigs and mod by N
>>> s = (s_1 + s_2) % N  #/
>>> # get the nonce point from the context
>>> r = context.nonce_point  #/
>>> # create the Schnorr Signature using the r and the s
>>> sig = SchnorrSignature(r, s)  #/
>>> # check the validity of the schnorr signature using the group point from the context
>>> print(context.group_point.verify_schnorr(msg, sig))  #/
True

#endexercise
#unittest
musig:PartialSigTest:test_verify:
#endunittest
#unittest
musig:PartialSigTest:test_sign:
#endunittest
#exercise

Trade partial signatures with your neighbor and verify for the message from Exercise 10. 

----
>>> from ecc import N, PrivateKey
>>> from hash import hash_musignoncecoef
>>> from helper import big_endian_to_int, sha256
>>> from musig import NoncePrivateShare, NoncePublicShare, MuSigParticipant, MuSigCoordinator
>>> msg = b"Love thy neighbor"
>>> my_secret = big_endian_to_int(sha256(b"jimmy@programmingblockchain.com"))  #/my_secret = big_endian_to_int(sha256(b"<my email address>"))
>>> me = MuSigParticipant(PrivateKey(my_secret))
>>> my_pubkey = me.point
>>> neighbor_pubkey = S256Point.parse(bytes.fromhex("02e79c4eb45764bd015542f6779cc70fef44b7a2432f839264768288efab886291"))  #/neighbor_pubkey = S256Point.parse(bytes.fromhex("<my neighbor's sec pubkey>"))
>>> # create the coordinator with me and my neighbor
>>> coor = MuSigCoordinator([my_pubkey, neighbor_pubkey])  #/
>>> # generate my nonce share using generate_nonce_share
>>> my_nonce_share = me.generate_nonce_share(msg=msg, rand=b'')  #/
>>> # print the nonce share's serialization in hex and share with your neighbor
>>> print(my_nonce_share.serialize().hex())  #/
03d2b367270076e3cf7f7b3eb03231fea9ba0143b702fd14b196c36b7e7edc8213021e336acb6087523fe8b2f5c5d25fa8debfa4427af16e490c3020e9dff89970bf
>>> neighbor_share = NoncePublicShare.parse(bytes.fromhex("02047885833379c1f0fdc64ebf7a7741e530d111bd0a4dacabeb4ff657040bfa1503fcd6c272723feb9fecbd0efe06d02dd17c3f7ef5088764280109eadd88044417"))  #/ neighbor_share = NoncePublicShare.parse(bytes.fromhex("<fill in with your neighbor's hex public nonce share>"))
>>> # register my nonce share to the coordinator
>>> coor.register_nonce_share(me.point.sec(), my_nonce_share)  #/
>>> # register neighbor's share to the coordinator
>>> coor.register_nonce_share(neighbor_pubkey.sec(), neighbor_share)  #/
>>> # create the signing context
>>> context = coor.create_signing_context(msg)  #/
>>> # sign with the context
>>> my_partial_sig = me.sign(context)  #/
>>> # print the partial sig in hex to share with your neighbor
>>> print(my_partial_sig.hex())  #/
339e3a2623c6428fbfb0c9c3d96cad040c3558583feeb090cfbe9dbdef1e7cdd
>>> neighbor_sig = bytes.fromhex("3df44541f373d621782508e74bf824903d34861ef3c3c0d366791161c5a34995")  #/neighbor_sig = bytes.fromhex("<fill in with your neighbor's partial sig in hex>") 
>>> # sum the two partial sigs converted to integers and then mod by N
>>> s = (big_endian_to_int(my_partial_sig) + big_endian_to_int(neighbor_sig)) % N  #/
>>> # get the nonce point from the context
>>> r = context.nonce_point  #/
>>> # create the Schnorr Signature using the r and the s
>>> sig = SchnorrSignature(r, s)  #/
>>> # check the validity of the schnorr signature using the group point from the context
>>> print(context.group_point.verify_schnorr(msg, sig))  #/
True

#endexercise
#markdown
# MuSig2 Group Point Tweaking
* If the MuSig2 group point is the KeyPath Spend, then there is a tweak $t$
* The group point $P$ and tweak $t$ make the external pubkey $Q=P+tG$
* $Q$ is $x$-only, so that determines $e_i$ negation, not the $P$
* We set $Q$ to be the group point
#endmarkdown
#code
>>> # example of tweaking the MuSig2 group pubkey
>>> from ecc import G, PrivateKey
>>> from hash import hash_taptweak
>>> from helper import big_endian_to_int
>>> from musig import KeyAggregator
>>> pubkeys = [PrivateKey(i * 1000).point for i in range(1,7)]
>>> keyagg = KeyAggregator(pubkeys)
>>> merkle_root = b""
>>> tweak = hash_taptweak(keyagg.group_point.xonly() + merkle_root)
>>> t = big_endian_to_int(tweak)
>>> keyagg.group_point = keyagg.group_point + t * G
>>> print(keyagg.group_point.sec().hex())
03848739171dfa90beb227101b38871dafa7db835d0ba4bb1279a3d0d0ea8e91b5

#endcode
#markdown
# Partial Sig Aggregation for even/odd $Q$
* For even $Q$: the Schnorr Signature $(R, s+td)$ will validate for the tweaked key $Q$
* For odd $Q$: The Schnorr Signature $(R, s-td)$ will validate for the tweaked key $-Q$
#endmarkdown
#code
>>> # example of aggregating a tweaked group pubkey
>>> from ecc import G, N, PrivateKey, SchnorrSignature
>>> from helper import big_endian_to_int
>>> from musig import SigningContext, MuSigParticipant, MuSigCoordinator
>>> participant_1 = MuSigParticipant(PrivateKey(1000))
>>> participant_2 = MuSigParticipant(PrivateKey(2000))
>>> msg = b"Hello World!"
>>> nonce_share_1 = NoncePrivateShare(3000, 4000, participant_1.point)
>>> nonce_share_2 = NoncePrivateShare(5000, 6000, participant_2.point)
>>> participant_1.nonce_private_share = nonce_share_1
>>> participant_2.nonce_private_share = nonce_share_2
>>> pubkeys = [participant_1.point, participant_2.point]
>>> coor = MuSigCoordinator(pubkeys)
>>> tweak = hash_taptweak(coor.keyagg.group_point.xonly() + b"")
>>> t = big_endian_to_int(tweak)
>>> coor.keyagg.group_point = coor.keyagg.group_point + t * G
>>> coor.register_nonce_share(participant_1.point.sec(), nonce_share_1.public_share)
>>> coor.register_nonce_share(participant_2.point.sec(), nonce_share_2.public_share)
>>> context = coor.create_signing_context(msg)
>>> s_1 = big_endian_to_int(participant_1.sign(context))
>>> s_2 = big_endian_to_int(participant_2.sign(context))
>>> s = (s_1 + s_2) % N
>>> d = context.challenge
>>> if context.group_point.even:
...     s = (s + d * t) % N
... else:
...     s = (s - d * t) % N
>>> r = context.nonce_point
>>> sig = SchnorrSignature(r, s)
>>> print(context.group_point.verify_schnorr(msg, sig))
True

#endcode
#exercise

Sum the partial signatures, create a Schnorr Signature and verify it using the group point

----
>>> from ecc import G, N, PrivateKey, SchnorrSignature
>>> from musig import SigningContext, MuSigParticipant, MuSigCoordinator
>>> participant_1 = MuSigParticipant(PrivateKey(1000))
>>> participant_2 = MuSigParticipant(PrivateKey(2000))
>>> msg = b"Hello World!"
>>> nonce_share_1 = NoncePrivateShare(3000, 4000, participant_1.point)
>>> nonce_share_2 = NoncePrivateShare(5000, 6000, participant_2.point)
>>> participant_1.nonce_private_share = nonce_share_1
>>> participant_2.nonce_private_share = nonce_share_2
>>> pubkeys = [participant_1.point, participant_2.point]
>>> merkle_root = bytes.fromhex("818c9d665b78324ba673afca23f5f4f5512214ccfd0554fe82c5f99f5a29689a")
>>> coor = MuSigCoordinator(pubkeys, merkle_root=merkle_root)
>>> t = coor.keyagg.tweak_amount
>>> coor.register_nonce_share(participant_1.point.sec(), nonce_share_1.public_share)
>>> coor.register_nonce_share(participant_2.point.sec(), nonce_share_2.public_share)
>>> context = coor.create_signing_context(msg)
>>> s_1 = 0xa23b11cb8c2120ac414f15fc27f67f4588f770b1e3a2012406a8771287410da1
>>> s_2 = 0x22d4db66c5a3bfecf63ac2b6402a5cba717938d33006a0ee8b1d398aee9dda1e
>>> # sum the two partial sigs and mod by N
>>> s = (s_1 + s_2) % N  #/
>>> # get the challenge from the context
>>> d = context.challenge  #/
>>> # add d*t to s if group point is even, subtract d*t from s if odd
>>> if context.group_point.even:  #/
...     s = (s + d * t) % N  #/
... else:  #/
...     s = (s - d * t) % N  #/
>>> # get the nonce point from the context
>>> r = context.nonce_point  #/
>>> # create the Schnorr Signature using the r and the s
>>> sig = SchnorrSignature(r, s)  #/
>>> # check the validity of the schnorr signature using the group point from the context
>>> print(context.group_point.verify_schnorr(msg, sig))  #/
True

#endexercise
#unittest
musig:PartialSigTest:test_compute_sig:
#endunittest
#exercise

Trade partial signatures with your neighbor and verify for the message from Exercise 10. 

----
>>> from ecc import N, PrivateKey
>>> from hash import hash_musignoncecoef
>>> from helper import big_endian_to_int, sha256
>>> from musig import NoncePrivateShare, NoncePublicShare, MuSigParticipant, MuSigCoordinator
>>> msg = b"Love thy neighbor"
>>> my_secret = big_endian_to_int(sha256(b"jimmy@programmingblockchain.com"))  #/my_secret = big_endian_to_int(sha256(b"<my email address>"))
>>> me = MuSigParticipant(PrivateKey(my_secret))
>>> my_pubkey = me.point
>>> neighbor_pubkey = S256Point.parse(bytes.fromhex("02e79c4eb45764bd015542f6779cc70fef44b7a2432f839264768288efab886291"))  #/Neighbor_pubkey = S256Point.parse(bytes.fromhex("<my neighbor's sec pubkey>"))
>>> merkle_root = bytes.fromhex("818c9d665b78324ba673afca23f5f4f5512214ccfd0554fe82c5f99f5a29689a")
>>> # create the coordinator with my pubkey and my neighbor's pubkey with the merkle root
>>> coor = MuSigCoordinator([my_pubkey, neighbor_pubkey], merkle_root)  #/
>>> # generate my nonce share using generate_nonce_share
>>> my_nonce_share = me.generate_nonce_share(msg=msg, rand=b'')  #/
>>> # print the nonce share's serialization in hex and share with your neighbor
>>> print(my_nonce_share.serialize().hex())  #/
03d2b367270076e3cf7f7b3eb03231fea9ba0143b702fd14b196c36b7e7edc8213021e336acb6087523fe8b2f5c5d25fa8debfa4427af16e490c3020e9dff89970bf
>>> neighbor_share = NoncePublicShare.parse(bytes.fromhex("02047885833379c1f0fdc64ebf7a7741e530d111bd0a4dacabeb4ff657040bfa1503fcd6c272723feb9fecbd0efe06d02dd17c3f7ef5088764280109eadd88044417"))  #/neighbor_share = NoncePublicShare.parse(bytes.fromhex("<fill in with your neighbor's hex public nonce share>"))
>>> # register my nonce share to the coordinator
>>> coor.register_nonce_share(me.point.sec(), my_nonce_share)  #/
>>> # register neighbor's share to the coordinator
>>> coor.register_nonce_share(neighbor_pubkey.sec(), neighbor_share)  #/
>>> # create the signing context
>>> context = coor.create_signing_context(msg)  #/
>>> # sign with the context
>>> my_partial_sig = me.sign(context)  #/
>>> # register my partial signature with the coordinator
>>> coor.register_partial_sig(me.point.sec(), my_partial_sig)  #/
>>> # print the partial sig in hex to share with your neighbor
>>> print(my_partial_sig.hex())  #/
962ccde215f7474a6d3e4573345f5ade437828d609b4cc96d2d7b38b7cab3873
>>> neighbor_sig = bytes.fromhex("ee6e049ed6fbfa5db541c752e3b8d693e63b5b523dc57e8ca2345c4cf239d599")  #/neighbor_sig = bytes.fromhex("<fill in with your neighbor's partial sig in hex>")
>>> # register neighbor's sig with the coordinator
>>> coor.register_partial_sig(neighbor_pubkey.sec(), neighbor_sig)  #/
>>> # get the schnorr signature from the coordinator
>>> sig = coor.compute_sig()  #/
>>> # print whether the signature verifies
>>> print(coor.group_point.verify_schnorr(msg, sig))  #/
True
>>> # print the signature, serialized in hex
>>> print(sig.serialize().hex())  #/
81af2a4d742d4b6116bb2fbdcf7196384fb2672e3c3dd04b16983851e900554aa5542e137f0688a627e74abc6400b2336a66b22a21a570ed3aa5ef24eb31a17e

#endexercise
#exercise

Make an address with your neighbor where the internal pubkey is a 2-of-2 MuSig and the single TapLeaf is also a 2-of-2 MuSig

Submit your address at [this link](https://docs.google.com/spreadsheets/d/1BHqFAzgfThrf64q9pCinwTd7FitJrL5Is3HHBR3UyeI/edit?usp=sharing)


----
>>> from ecc import N, PrivateKey
>>> from hash import hash_musignoncecoef
>>> from helper import big_endian_to_int, sha256
>>> from musig import KeyAggregator, MuSigParticipant, MuSigCoordinator
>>> from taproot import TapLeaf, TapScript
>>> my_secret = big_endian_to_int(sha256(b"jimmy@programmingblockchain.com"))  #/my_secret = big_endian_to_int(sha256(b"<my email address>"))
>>> me = MuSigParticipant(PrivateKey(my_secret))
>>> neighbor_pubkey = S256Point.parse(bytes.fromhex("02e79c4eb45764bd015542f6779cc70fef44b7a2432f839264768288efab886291"))  #/neighbor_pubkey = S256Point.parse(bytes.fromhex("<my neighbor's sec pubkey>"))
>>> # collect the pubkeys in a list
>>> pubkeys = [me.point, neighbor_pubkey]  #/
>>> # use the KeyAggregator to get the pubkey
>>> group_point = KeyAggregator(pubkeys).group_point  #/
>>> # the TapScript we want is [P, 0xAC] where P is the group point in xonly, 0xAC is OP_CHECKSIG
>>> ts = TapScript([group_point.xonly(), 0xAC])  #/
>>> # create a TapLeaf with the single TapScript
>>> leaf = TapLeaf(ts)  #/
>>> # set the merkle root to be the hash of this TapLeaf
>>> merkle_root = leaf.hash()  #/
>>> # create the coordinator with pubkeys with the merkle root
>>> coor = MuSigCoordinator([me.point, neighbor_pubkey], merkle_root)  #/
>>> # use the address method to get the p2tr address on signet
>>> print(coor.address(network="signet"))  #/
tb1pjp69sgyhqnwhsmrtlxr55fykdk526eu3x5wyvmed0jhjx9jdzq8qr9zgqg

#endexercise
"""

FUNCTIONS = """
musig.KeyAggregator.compute_group_commitment
musig.KeyAggregator.compute_group_point
musig.KeyAggregator.keyagg_coef
musig.MuSigCoordinator.compute_nonce_point
musig.MuSigCoordinator.compute_sig
musig.MuSigParticipant.sign
musig.SigningContext.verify
"""
