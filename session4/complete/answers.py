"""
#code
>>> import frost

#endcode
#code
>>> # Example MuSig2 Spend
>>> from ecc import N, PrivateKey, S256Point
>>> from musig import KeyAggregator, NoncePublicShare, MuSigParticipant, MuSigCoordinator
>>> from script import address_to_script_pubkey
>>> from taproot import TapScript, TapLeaf
>>> from tx import TxIn, TxOut, Tx
>>> my_secret = 21000000
>>> me = MuSigParticipant(PrivateKey(my_secret))
>>> neighbor_pubkey = S256Point.parse(bytes.fromhex("029addad123cfcfa19c501dd1f15ca93b74a57ef88aa34035470dd46e54b5931c6"))
>>> pubkeys = [me.point, neighbor_pubkey]
>>> keyagg = KeyAggregator(pubkeys)
>>> group_point = keyagg.group_point
>>> ts = TapScript([group_point.xonly(), 0xAC])
>>> leaf = TapLeaf(ts)
>>> merkle_root = leaf.hash()
>>> coor = MuSigCoordinator(pubkeys, merkle_root)
>>> prev_tx = bytes.fromhex("4b5fbb9de406a16e133fdb9ea0adcfa2dac40c1f6b82e4b58d5ce28229618f1c")
>>> prev_index = 0
>>> fee = 500
>>> tx_in = TxIn(prev_tx, prev_index)
>>> target_amount = tx_in.value(network="signet") - fee
>>> target_script = address_to_script_pubkey("tb1q7kn55vf3mmd40gyj46r245lw87dc6us5n50lrg")
>>> tx_out = TxOut(target_amount, target_script)
>>> tx_obj = Tx(1, [tx_in], [tx_out], network="signet", segwit=True)
>>> msg = tx_obj.sig_hash(0)
>>> my_nonce_share = me.generate_nonce_share(msg=msg, aggregate_pubkey=group_point, rand=b'')
>>> print(my_nonce_share.serialize().hex())
02051d617f5d3cf975e3a2fae4e812927fa5d239d7a14615ecdb86b3131c520325031f7e92929762fc2f052e8085b149f96b206517886b9e01deade37eddfdd1b984
>>> neighbor_share = NoncePublicShare.parse(bytes.fromhex("02d8ffef7503cec7a5046d238f53d5f599e57772813aa8b4c1cbd017a453fbcd25026bc7edd0264573f8e90e2f1d6753b0004010d8d1c235f5f1c44995f5376a0e81"))
>>> coor.register_nonce_share(me.point.sec(), my_nonce_share)
>>> coor.register_nonce_share(neighbor_pubkey.sec(), neighbor_share)
>>> context = coor.create_signing_context(msg)
>>> my_partial_sig = me.sign(context)
>>> coor.register_partial_sig(me.point.sec(), my_partial_sig)
>>> print(my_partial_sig.hex())
1b61c7bc63a1c31c8e351613d55b362dd1003c31b326ca561b6c2b5cdc457a41
>>> neighbor_sig = bytes.fromhex("82420b4a9accb4392eb850cb1853849a03a35711f3d7ae112eff9fd3214bc538")
>>> coor.register_partial_sig(neighbor_pubkey.sec(), neighbor_sig)
>>> sig = coor.compute_sig().serialize()
>>> tx_in.finalize_p2tr_keypath(sig)
>>> print(tx_obj.verify())
True
>>> print(tx_obj.serialize().hex())
010000000001011c8f612982e25c8db5e4826b1f0cc4daa2cfada09edb3f136ea106e49dbb5f4b0000000000ffffffff01ac84010000000000160014f5a74a3131dedb57a092ae86aad3ee3f9b8d7214014019b2549a87ea205c5b7e2b12928aef2f242cb42dc4b626b29da209af3e1fdcfab3cb97cd4a3cf23d7926e05c847047ff2a50de6af57aadfd2c79b9066caa721600000000

#endcode
#exercise

You have been sent 2 UTXOs to the address you created in the last session.
KeyPath spend one of the UTXO to <code>tb1q7kn55vf3mmd40gyj46r245lw87dc6us5n50lrg</code>. Use <a href="https://mempool.space/signet/tx/push to broadcast your transaction" target="_mempool">Mempool Signet</a> to broadcast your transaction.

----
>>> from ecc import N, PrivateKey, S256Point
>>> from helper import big_endian_to_int, sha256
>>> from musig import KeyAggregator, NoncePublicShare, MuSigParticipant, MuSigCoordinator
>>> from script import address_to_script_pubkey
>>> from taproot import TapScript, TapLeaf
>>> from tx import TxIn, TxOut, Tx
>>> from witness import Witness
>>> my_secret = big_endian_to_int(sha256(b"jimmy@programmingblockchain.com"))  #/my_secret = big_endian_to_int(sha256(b"<my email address>"))
>>> me = MuSigParticipant(PrivateKey(my_secret))
>>> neighbor_pubkey = S256Point.parse(bytes.fromhex("02e79c4eb45764bd015542f6779cc70fef44b7a2432f839264768288efab886291"))  #/neighbor_pubkey = S256Point.parse(bytes.fromhex("<my neighbor's sec pubkey>"))
>>> pubkeys = [me.point, neighbor_pubkey]
>>> keyagg = KeyAggregator(pubkeys)
>>> group_point = keyagg.group_point
>>> ts = TapScript([group_point.xonly(), 0xAC])
>>> leaf = TapLeaf(ts)
>>> merkle_root = leaf.hash()
>>> print(group_point.p2tr_address(merkle_root, network="signet"))
tb1pjp69sgyhqnwhsmrtlxr55fykdk526eu3x5wyvmed0jhjx9jdzq8qr9zgqg
>>> coor = MuSigCoordinator(pubkeys, merkle_root)
>>> prev_tx = bytes.fromhex("7b4699e1154a38a63c560216f3481c19e97d4b07aa654f7a205442d7f7937710")  #/prev_tx = bytes.fromhex("<fiil me in>")
>>> prev_index = 0  #/prev_index = -1  # change me!
>>> fee = 500
>>> # create a transaction input with the previous tx and index
>>> tx_in = TxIn(prev_tx, prev_index)  #/
>>> # calculate the amount using the value in the UTXO minus the fee
>>> target_amount = tx_in.value(network="signet") - fee  #/
>>> target_address = "tb1q7kn55vf3mmd40gyj46r245lw87dc6us5n50lrg"
>>> # use the address_to_script_pubkey method to get the output script pubkey
>>> target_script = address_to_script_pubkey(target_address)  #/
>>> # create the TxOut
>>> tx_out = TxOut(target_amount, target_script)  #/
>>> # create the Tx (remember network="signet" and segwit=True)
>>> tx_obj = Tx(1, [tx_in], [tx_out], network="signet", segwit=True)  #/
>>> # set the message to be the sig_hash on index 0
>>> msg = tx_obj.sig_hash(0)  #/
>>> # generate a nonce
>>> my_nonce_share = me.generate_nonce_share(msg=msg, aggregate_pubkey=group_point, rand=b'')  #/
>>> # print the nonce share serialized in hex for your neighbor
>>> print(my_nonce_share.serialize().hex())  #/
03afaedbbd00b36d4d0cb5e12774b3db480daa0089fb328ebc9c57d3b8c3c1322102dda103bd9ea96754e244697c0dcee76254a76b5ebd1c3d26d8374192f7dd489a
>>> neighbor = MuSigParticipant(PrivateKey(21000000))
>>> ns = neighbor.generate_nonce_share(msg=msg, aggregate_pubkey=group_point, rand=b'')
>>> print(ns.serialize().hex())
02f903cf6bd3481f7061a5f2d3d556e4415df7b8baa732c2224d14320802e4db1f02e5936ece2ad2a75665e8d1e8810089abe821f74faa10dbdc55c8481e2da90449
>>> # grab your neighbor's nonce
>>> neighbor_share = NoncePublicShare.parse(bytes.fromhex("02f903cf6bd3481f7061a5f2d3d556e4415df7b8baa732c2224d14320802e4db1f02e5936ece2ad2a75665e8d1e8810089abe821f74faa10dbdc55c8481e2da90449"))  #/neighbor_share = NoncePublicShare.parse(bytes.fromhex("<fill in>"))
>>> # register both nonces with the coordinator
>>> coor.register_nonce_share(me.point.sec(), my_nonce_share)  #/
>>> coor.register_nonce_share(neighbor_pubkey.sec(), neighbor_share)  #/
>>> # create the signing context using the message
>>> context = coor.create_signing_context(msg)  #/
>>> print(neighbor.sign(context).hex())
0c97c1ba20e2ff12c940ca341a5947ebb8d3a2454689e6fb52ed49961e6a7c3e
>>> # create your own partial sig using the context
>>> my_partial_sig = me.sign(context)  #/
>>> # register the partial sig with the coordinator
>>> coor.register_partial_sig(me.point.sec(), my_partial_sig)  #/
>>> # print the hex of the partial signature
>>> print(my_partial_sig.hex())  #/
64fc2873978844f82a70101e3765c7e8b3b8db939d4b5a7d6e315d6929ba988f
>>> # grab your neighbor's partial signature
>>> neighbor_sig = bytes.fromhex("0c97c1ba20e2ff12c940ca341a5947ebb8d3a2454689e6fb52ed49961e6a7c3e")  #/neighbor_sig = bytes.fromhex("<fill in>")
>>> # register your neighbor's partial sig
>>> coor.register_partial_sig(neighbor_pubkey.sec(), neighbor_sig)  #/
>>> # compute the schnorr signature and serialize it
>>> sig = coor.compute_sig().serialize()  #/
>>> # use the TxIn's finalize_p2tr_keypath to insert the signature to the transaction
>>> tx_in.finalize_p2tr_keypath(sig)  #/
>>> # check that the transaction verifies
>>> print(tx_obj.verify())  #/
True
>>> # print the serialization of the tx in hex and broadcast it on https://mempool.space/signet/tx/push
>>> print(tx_obj.serialize().hex())  #/
01000000000101107793f7d74254207a4f65aa074b7de9191c48f31602563ca6384a15e199467b0000000000ffffffff01ac84010000000000160014f5a74a3131dedb57a092ae86aad3ee3f9b8d721401409817763d11851ccfd50b7819a44b9ff65bbff604eacda483db6eff9096dad07aeab3311ed3a0b4064c555995b0004d5ac42eb317b59716c0fff0b1c7904e55b400000000

#endexercise
#exercise

BONUS! Don't do this one unless you finished the previous exercise and have time. You have been sent 2 UTXOs to the address you created in the last session. ScriptPath spend the UTXO you haven't spent yet to the same address. Use <a href="https://mempool.space/signet/tx/push to broadcast your transaction" target="_mempool">Mempool Signet</a> to broadcast your transaction.

----
>>> from ecc import N, PrivateKey, S256Point
>>> from helper import big_endian_to_int, sha256
>>> from musig import KeyAggregator, NoncePublicShare, MuSigParticipant, MuSigCoordinator
>>> from script import address_to_script_pubkey
>>> from taproot import TapScript, TapLeaf
>>> from tx import TxIn, TxOut, Tx
>>> from witness import Witness
>>> my_secret = big_endian_to_int(sha256(b"jimmy@programmingblockchain.com"))  #/my_secret = big_endian_to_int(sha256(b"<my email address>"))
>>> me = MuSigParticipant(PrivateKey(my_secret))
>>> neighbor_pubkey = S256Point.parse(bytes.fromhex("02e79c4eb45764bd015542f6779cc70fef44b7a2432f839264768288efab886291"))  #/neighbor_pubkey = S256Point.parse(bytes.fromhex("<my neighbor's sec pubkey>"))
>>> pubkeys = [me.point, neighbor_pubkey]
>>> keyagg = KeyAggregator(pubkeys)
>>> group_point = keyagg.group_point
>>> tap_script = TapScript([group_point.xonly(), 0xAC])
>>> tap_leaf = tap_script.tap_leaf()
>>> coor = MuSigCoordinator(pubkeys)
>>> prev_tx = bytes.fromhex("eefd10cd30e7a62c2ac9945e383f7e5ae606edfc5fa301b7951e94f8e04558c8")  #/prev_tx = bytes.fromhex("<fiil me in>")
>>> prev_index = 0  #/prev_index = -1  # change me!
>>> fee = 500
>>> # create a transaction input with the previous tx and index
>>> tx_in = TxIn(prev_tx, prev_index)  #/
>>> # calculate the amount using the value in the UTXO minus the fee
>>> target_amount = tx_in.value(network="signet") - fee  #/
>>> target_address = "tb1q7kn55vf3mmd40gyj46r245lw87dc6us5n50lrg"
>>> # use the address_to_script_pubkey method to get the output script pubkey
>>> target_script = address_to_script_pubkey(target_address)  #/
>>> # create the TxOut
>>> tx_out = TxOut(target_amount, target_script)  #/
>>> # create the Tx (remember network="signet" and segwit=True)
>>> tx_obj = Tx(1, [tx_in], [tx_out], network="signet", segwit=True)  #/
>>> # create the control block from the TapLeaf passing in the group point
>>> cb = tap_leaf.control_block(group_point)  #/
>>> # set the tx_in's witness to be a new witness with two elements, the tap_script raw serialized and the control block serialized
>>> tx_in.witness = Witness([tap_script.raw_serialize(), cb.serialize()])  #/
>>> # set the message to be the sig_hash on index 0
>>> msg = tx_obj.sig_hash(0)  #/
>>> # generate a nonce
>>> my_nonce_share = me.generate_nonce_share(msg=msg, aggregate_pubkey=group_point, rand=b'')  #/
>>> # print the nonce share serialized in hex for your neighbor
>>> print(my_nonce_share.serialize().hex())  #/
03d3400f5192f10ee23b4bf548aac097602a3dc7ebfb42b6b6942f89cf118cb8c503f75a25822709e49219a486f4202d158f9dedc69a18b9c57e650a9ded6901d53f
>>> # grab your neighbor's nonce
>>> neighbor_share = NoncePublicShare.parse(bytes.fromhex("039c025e58f3c85e8b78b31418cc3ca372285c48310f7e034da1bde6a61d3e21850295e6031d9301f1bce466dc8dc0636007882dce665f2521a76f96d403599e8e33"))  #/neighbor_share = NoncePublicShare.parse(bytes.fromhex("<fill in>"))
>>> # register both nonces with the coordinator
>>> coor.register_nonce_share(me.point.sec(), my_nonce_share)  #/
>>> coor.register_nonce_share(neighbor_pubkey.sec(), neighbor_share)  #/
>>> # create the signing context using the message
>>> context = coor.create_signing_context(msg)  #/
>>> # create your own partial sig using the context
>>> my_partial_sig = me.sign(context)  #/
>>> # register the partial sig with the coordinator
>>> coor.register_partial_sig(me.point.sec(), my_partial_sig)  #/
>>> # print the hex of the partial signature
>>> print(my_partial_sig.hex())  #/
ddee9157385eeb894d15b547665555e5d79c12c596dc5b7e509b528d8f6c941a
>>> # grab your neighbor's partial signature
>>> neighbor_sig = bytes.fromhex("eefbf92cd0914d698f379ccbc2911234a5c2e6b5fc71823ef8bf3c8b889e7e3c")  #/neighbor_sig = bytes.fromhex("<fill in>")
>>> # register your neighbor's partial sig
>>> coor.register_partial_sig(neighbor_pubkey.sec(), neighbor_sig)  #/
>>> # compute the schnorr signature and serialize it
>>> sig = coor.compute_sig()  #/
>>> # insert the sig in front of the other elements in the witness using tx_in.witness.items.insert
>>> tx_in.witness.items.insert(0, sig.serialize())  #/
>>> # check that the transaction verifies
>>> print(tx_obj.verify())  #/
True
>>> # print the serialization of the tx in hex and broadcast it on https://mempool.space/signet/tx/push
>>> print(tx_obj.serialize().hex())  #/
01000000000101c85845e0f8941e95b701a35ffced06e65a7e3f385e94c92a2ca6e730cd10fdee0000000000ffffffff01ac84010000000000160014f5a74a3131dedb57a092ae86aad3ee3f9b8d7214034014b58fc7aa169918b19a0b0f2fd30784331c9f222f4dafa71b08aea1b70d244accea8a8408f038f2dc4d521328e6681bc2b01c94e4053d818988308c47d4d11522209eb76b0b34923d2f924716eef038cd59cb9fcf3a79841f5069e0e5503eb67838ac21c09eb76b0b34923d2f924716eef038cd59cb9fcf3a79841f5069e0e5503eb6783800000000

#endexercise
#markdown
# Trusted Dealer Setup
* Dealer generates a secret $e$
* Dealer creates a degree $t-1$ polynomial with random coefficients $a_1,...,a_{t-1}$
* The dealer creates a polynomial $f(x)=e+a_1x+a_2x^2+...+a_{t-1}x^{t-1}$
* $f(0)=e$ so that's where the secret is
* Participant $x$ gets dealt $f(x)=y_x$ $\forall{x} \in {1,2,...,n}$
* $y_x$ is the share of the secret
#endmarkdown
#code
>>> # Example 3-of-5 Shamir
>>> from frost import PrivatePolynomial
>>> poly = PrivatePolynomial([1000, 2000, 3000])
>>> shares = {}
>>> for x in range(1, 6):
...    shares[x] = poly.y_value(x)
>>> print(shares[5])
86000

#endcode
#exercise

Create 7 shares whose threshold is 4

----
>>> from frost import PrivatePolynomial
>>> poly = PrivatePolynomial([1000, 2000, 3000, 4000])
>>> shares = {x: poly.y_value(x) for x in range(1, 8)}
>>> print(shares[6])
985000

#endexercise
#markdown
# Lagrange Interpolation Polynomial
* For a participant at $x_i$ where $X = \{x_1, x_2, ... x_t\}$
* Goal is a $t-1$ degree polynomial $g(x)$ such that: $g(x_i)=1$ and $g(x_j)=0$ where $j\ne i$
* Note $g(x_j)=0$ if $g(x)=(x-x_j)h(x)$
* Let $h(x)=\prod_{j \ne i}{(x-x_j)}$
* Note $h(x)$ is degree $t-1$
* We note $h(x_i) = \prod_{j \ne i}{(x_i-x_j)}$
* $g(x) = h(x)/h(x_i)$, $g(x_i)=h(x_i)/h(x_i)=1$ and $g(x_j)=0$ where $j\ne i$
#endmarkdown
#code
>>> # make a lagrange poly with X = {1, 3, 4} for participant 4
>>> def g(x):
...     participants = [1, 3, 4]
...     x_i = 4
...     product = 1
...     for x_j in participants:
...         if x_j != x_i:
...             product *= (x-x_j) * pow(x_i - x_j, -1, N) % N
...     return product
>>> print(g(1), g(3), g(4), g(55))
0 0 1 936

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
>>> for p_i in pubkeys:  #/
...     # if the second point is None and the pubkey is not the first one
...     if second_point is None and p_i != pubkeys[0]:  #/
...         # then designate the second point to be this pubkey
...         second_point = p_i  #/
...     # if the current pubkey is the second point, c_i is 1
...     if p_i == second_point:  #/
...         c_i = 1  #/
...     # otherwise
...     else:  #/
...         # calculate the hash of the group commitment and the sec
...         h = hash_keyaggcoef(group_commitment + p_i.sec())  #/
...         # convert the hash to an integer
...         c_i = big_endian_to_int(h)  #/
...     # add the coefficient * pubkey to the list of terms
...     terms.append(c_i * p_i)  #/
>>> # the group pubkey is the sum of the terms
>>> p = S256Point.sum(terms)  #/
>>> # print the group pubkey's sec in hex
>>> print(p.sec().hex())
03628b3911ec6818290dbc40e0039652ceac6bef4355c6b461af870d0aafa123a0

#endexercise
#unittest
musig:KeyAggTest:test_compute_group_commitment:
#endunittest
#unittest
musig:KeyAggTest:test_compute_group_point:
#endunittest
#exercise

Create a 2-of-2 BIP327 public key sharing a key with your neighbor.

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
...     nonce_share = p.generate_nonce_share(rand=b'')
...     coor.register_nonce_share(p.point.sec(), nonce_share)
>>> group_point = coor.keyagg.group_point
>>> s = S256Point.sum([n.s for n in coor.nonce_shares.values()])
>>> t = S256Point.sum([n.t for n in coor.nonce_shares.values()])
>>> h = hash_musignoncecoef(s.sec()+t.sec()+group_point.xonly()+msg)
>>> b = big_endian_to_int(h)
>>> r = s + b*t
>>> print(r.sec().hex())
038f12dde9f661cdd1d655a6fa8ac600de344550a1d70f1c0f5376e2600fa94a6b
>>> k = (participants[0].private_share.l + b * participants[0].private_share.m) % N
>>> print(hex(k))
0xb17767a513f759bda07c356a8292cb41d05ca7aaecdaeb6d3067be2d4386a5df

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
>>> # calculate the hash of s's sec, t's sec, p's xonly and the message, z
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
>>> neighbor_pubkey = S256Point.parse(bytes.fromhex("02e79c4eb45764bd015542f6779cc70fef44b7a2432f839264768288efab886291"))  #/neighbor_pubkey = S256Point.parse(bytes.fromhex("<my neighbor's sec pubkey>"))
>>> # create the coordinator with me and my neighbor
>>> coor = MuSigCoordinator([me.point, neighbor_pubkey])  #/
>>> # generate my nonce share using generate_nonce_share
>>> my_nonce_share = me.generate_nonce_share(rand=b'')  #/
>>> # print the nonce share's serialization in hex and share with your neighbor
>>> print(my_nonce_share.serialize().hex())  #/
02ed93c7309ac71a5eca7ba626b373ce20f4040643b0ff3dd8702eddbe76aa9d7d03c58cad4713bd31c475b7cad30f4feb619233fb5c82cb464b20667e627cdac491
>>> neighbor_share = NoncePublicShare.parse(bytes.fromhex("03b8e4c988117005dce2e1fcb4216fa642cb6d78f591f9caca6763aaf751dba6c8036314b285c9d8c585ca40e9c916724f63bca66e6287bafd9ff386f11b142ecad7"))  #/ neighbor_share = NoncePublicShare.parse(bytes.fromhex("<fill in with your neighbor's hex public nonce share>"))
>>> # register my nonce share to the coordinator
>>> coor.register_nonce_share(me.point.sec(), my_nonce_share)  #/
>>> # register neighbor's share to the coordinator
>>> coor.register_nonce_share(neighbor_pubkey.sec(), neighbor_share)  #/
>>> # compute the nonce point from the coordinator
>>> r = coor.compute_nonce_point(msg)  #/
>>> # print the sec format in hex of the nonce point
>>> print(r.sec().hex())  #/
03412e4d8e337549adff12d2d24f5caeb7911bbe1ea98c6573ff382d7305f4ba64

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
>>> msg = b"Hello World!"
>>> nonce_share_1 = NoncePrivateShare(3000, 4000, participant_1.point)
>>> nonce_share_2 = NoncePrivateShare(5000, 6000, participant_2.point)
>>> participant_1.private_share = nonce_share_1
>>> participant_2.private_share = nonce_share_2
>>> pubkeys = [participant_1.point, participant_2.point]
>>> coor = MuSigCoordinator(pubkeys)
>>> coor.register_nonce_share(participant_1.point.sec(), nonce_share_1.public_share)
>>> coor.register_nonce_share(participant_2.point.sec(), nonce_share_2.public_share)
>>> context = coor.create_signing_context(msg)
>>> if context.nonce_point.even:
...     k = participant_1.nonce(context.nonce_coef())
... else:
...     k = N - participant_1.nonce(context.nonce_coef())
>>> if context.group_point.even:
...     e = participant_1.private_key.secret
... else:
...     e = N - participant_1.private_key.secret
>>> c = context.keyagg_coef(participant_1.point)
>>> d = context.challenge()
>>> s = (k + c * d * e) % N
>>> print(hex(s))
0x1aad95d9490e4b8599377ff6a546a1d075fb4242c749dbcbc010589e23c21776

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
>>> msg = b"Hello World!"
>>> nonce_share_1 = NoncePrivateShare(3000, 4000, participant_1.point)
>>> nonce_share_2 = NoncePrivateShare(5000, 6000, participant_2.point)
>>> participant_1.private_share = nonce_share_1
>>> participant_2.private_share = nonce_share_2
>>> pubkeys = [participant_1.point, participant_2.point]
>>> coor = MuSigCoordinator(pubkeys)
>>> coor.register_nonce_share(participant_1.point.sec(), nonce_share_1.public_share)
>>> coor.register_nonce_share(participant_2.point.sec(), nonce_share_2.public_share)
>>> context = coor.create_signing_context(msg)
>>> s = 0x1aad95d9490e4b8599377ff6a546a1d075fb4242c749dbcbc010589e23c21776
>>> if context.nonce_point.even:
...     r = nonce_share_1.public_share.nonce_point(context.nonce_coef())
... else:
...     r = -1 * nonce_share_1.public_share.nonce_point(context.nonce_coef())
>>> if context.group_point.even:
...     p = participant_1.point
... else:
...     p = -1 * participant_1.point
>>> c = context.keyagg_coef(participant_1.point)
>>> d = context.challenge()
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
>>> participant_1.private_share = nonce_share_1
>>> participant_2.private_share = nonce_share_2
>>> pubkeys = [participant_1.point, participant_2.point]
>>> coor = MuSigCoordinator(pubkeys)
>>> coor.register_nonce_share(participant_1.point.sec(), nonce_share_1.public_share)
>>> coor.register_nonce_share(participant_2.point.sec(), nonce_share_2.public_share)
>>> # create the signing context, which should aggregate the points
>>> context = coor.create_signing_context(msg)  #/
>>> # determine the first participant's nonce (k_i) from the nonce point's evenness
>>> if context.nonce_point.even:  #/
...     k = participant_2.nonce(context.nonce_coef())  #/
... else:  #/
...     k = N - participant_2.nonce(context.nonce_coef())  #/
>>> # determine the first participant's secret (e_i) from the group point's evenness
>>> if context.group_point.even:  #/
...     e = participant_2.private_key.secret  #/
... else:  #/
...     e = N - participant_2.private_key.secret  #/
>>> # use the context's keylagg_coef method to get the keyagg coefficient (c_i = H(L||P_i))
>>> c = context.keyagg_coef(participant_2.point)  #/
>>> # use the context's challenge method to get the group challenge (d = H(R||P||z))
>>> d = context.challenge()  #/
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
>>> participant_1.private_share = nonce_share_1
>>> participant_2.private_share = nonce_share_2
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
...     r = nonce_share_2.public_share.nonce_point(context.nonce_coef())  #/
... else:  #/
...     r = -1 * nonce_share_2.public_share.nonce_point(context.nonce_coef())  #/
>>> # determine the second participant's pubkey (P_i) from the group point's evenness
>>> if context.group_point.even:  #/
...     p = participant_2.point  #/
... else:  #/
...     p = -1 * participant_2.point  #/
>>> # get the keyagg coefficient (c) for the second participant
>>> c = context.keyagg_coef(participant_2.point)  #/
>>> # get the challenge for the group (d)
>>> d = context.challenge()  #/
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
>>> participant_1.private_share = nonce_share_1
>>> participant_2.private_share = nonce_share_2
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
>>> neighbor_pubkey = S256Point.parse(bytes.fromhex("02e79c4eb45764bd015542f6779cc70fef44b7a2432f839264768288efab886291"))  #/neighbor_pubkey = S256Point.parse(bytes.fromhex("<my neighbor's sec pubkey>"))
>>> # create the coordinator with me and my neighbor
>>> coor = MuSigCoordinator([me.point, neighbor_pubkey])  #/
>>> # generate my nonce share using generate_nonce_share
>>> my_nonce_share = me.generate_nonce_share(rand=b'')  #/
>>> # print the nonce share's serialization in hex and share with your neighbor
>>> print(my_nonce_share.serialize().hex())  #/
02ed93c7309ac71a5eca7ba626b373ce20f4040643b0ff3dd8702eddbe76aa9d7d03c58cad4713bd31c475b7cad30f4feb619233fb5c82cb464b20667e627cdac491
>>> neighbor_share = NoncePublicShare.parse(bytes.fromhex("03b8e4c988117005dce2e1fcb4216fa642cb6d78f591f9caca6763aaf751dba6c8036314b285c9d8c585ca40e9c916724f63bca66e6287bafd9ff386f11b142ecad7"))  #/ neighbor_share = NoncePublicShare.parse(bytes.fromhex("<fill in with your neighbor's hex public nonce share>"))
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
55da5f304e9b8f0ae843574d7979020902cfb5417f6b7e8a9625117096d7835b
>>> neighbor_sig = bytes.fromhex("b4df43368db5ba2ce3a2deea804f600fe67ba3104f3c5da8f584abaf6e5ee083")  #/neighbor_sig = bytes.fromhex("<fill in with your neighbor's partial sig in hex>") 
>>> # sum the two partial sigs and mod by N
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
037c08a17c0c1141d4dbc135ff4841474a525c3a645154c8ba642213a09cde4fd9

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
>>> participant_1.private_share = nonce_share_1
>>> participant_2.private_share = nonce_share_2
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
>>> d = context.challenge()
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
>>> participant_1.private_share = nonce_share_1
>>> participant_2.private_share = nonce_share_2
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
>>> d = context.challenge()  #/
>>> # add d*t to s if even, subtract d*t from s if odd
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
>>> neighbor_pubkey = S256Point.parse(bytes.fromhex("02e79c4eb45764bd015542f6779cc70fef44b7a2432f839264768288efab886291"))  #/neighbor_pubkey = S256Point.parse(bytes.fromhex("<my neighbor's sec pubkey>"))
>>> merkle_root = bytes.fromhex("818c9d665b78324ba673afca23f5f4f5512214ccfd0554fe82c5f99f5a29689a")
>>> # create the coordinator with me and my neighbor with the merkle root
>>> coor = MuSigCoordinator([me.point, neighbor_pubkey], merkle_root)  #/
>>> # generate my nonce share using generate_nonce_share
>>> my_nonce_share = me.generate_nonce_share(rand=b'')  #/
>>> # print the nonce share's serialization in hex and share with your neighbor
>>> print(my_nonce_share.serialize().hex())  #/
02ed93c7309ac71a5eca7ba626b373ce20f4040643b0ff3dd8702eddbe76aa9d7d03c58cad4713bd31c475b7cad30f4feb619233fb5c82cb464b20667e627cdac491
>>> neighbor_share = NoncePublicShare.parse(bytes.fromhex("03b8e4c988117005dce2e1fcb4216fa642cb6d78f591f9caca6763aaf751dba6c8036314b285c9d8c585ca40e9c916724f63bca66e6287bafd9ff386f11b142ecad7"))  #/ neighbor_share = NoncePublicShare.parse(bytes.fromhex("<fill in with your neighbor's hex public nonce share>"))
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
68a91aacf62557fed42d8cc4ca262051554f3fa11d06c5330413ef05291ee1e9
>>> neighbor_sig = bytes.fromhex("e247c38fa2322f5a468750970919ba45604332ba8dd8e91f323d42d90ccade25")  #/neighbor_sig = bytes.fromhex("<fill in with your neighbor's partial sig in hex>")
>>> # register neighbor's sig with the coordinator
>>> coor.register_partial_sig(neighbor_pubkey.sec(), neighbor_sig)  #/
>>> # get the schnorr signature from the coordinator
>>> sig = coor.compute_sig()  #/
>>> # print whether the signature verifies
>>> print(coor.group_point.verify_schnorr(msg, sig))  #/
True
>>> # print the signature, serialized in hex
>>> print(sig.serialize().hex())  #/
c26a3a9ed24ebb0ac3d8cb99bca92112339d88477a713de9b1d1740f2e4d0a179cf23b53f562f7698b50390768b8692690572c8b26510625ec98b19eca81cadc

#endexercise
"""

FUNCTIONS = """
"""
