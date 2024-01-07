"""
#code
>>> import frost

#endcode
#code
>>> # Example MuSig2 KeyPath Spend
>>> from ecc import N, PrivateKey, S256Point
>>> from musig import KeyAggregator, NoncePublicShare, MuSigParticipant, MuSigCoordinator
>>> from script import address_to_script_pubkey
>>> from taproot import TapScript, TapLeaf
>>> from tx import TxIn, TxOut, Tx
>>> my_secret = 21000000
>>> me = MuSigParticipant(PrivateKey(my_secret))
>>> my_pubkey = me.point
>>> neighbor_pubkey = S256Point.parse(bytes.fromhex("029addad123cfcfa19c501dd1f15ca93b74a57ef88aa34035470dd46e54b5931c6"))
>>> pubkeys = [my_pubkey, neighbor_pubkey]
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
>>> coor.register_nonce_share(my_pubkey.sec(), my_nonce_share)
>>> coor.register_nonce_share(neighbor_pubkey.sec(), neighbor_share)
>>> context = coor.create_signing_context(msg)
>>> my_partial_sig = me.sign(context)
>>> coor.register_partial_sig(my_pubkey.sec(), my_partial_sig)
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
>>> # grab your neighbor's nonce
>>> neighbor_share = NoncePublicShare.parse(bytes.fromhex("02f903cf6bd3481f7061a5f2d3d556e4415df7b8baa732c2224d14320802e4db1f02e5936ece2ad2a75665e8d1e8810089abe821f74faa10dbdc55c8481e2da90449"))  #/neighbor_share = NoncePublicShare.parse(bytes.fromhex("<fill in>"))
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
>>> my_pubkey = me.point
>>> neighbor_pubkey = S256Point.parse(bytes.fromhex("02e79c4eb45764bd015542f6779cc70fef44b7a2432f839264768288efab886291"))  #/neighbor_pubkey = S256Point.parse(bytes.fromhex("<my neighbor's sec pubkey>"))
>>> pubkeys = [my_pubkey, neighbor_pubkey]
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
* Signer $i$ gets dealt $f(x)=y_i \forall{i} \in {1,2,...,n}$
* $y_i$ is the share of the secret
#endmarkdown
#code
>>> # Example 3-of-5 Shamir
>>> from ecc import N
>>> coefficients = [21000000, 11111111, 2222222]
>>> shares = {}
>>> for x in range(1, 6):
...     y_value = 0
...     for i, coef in enumerate(coefficients):
...         y_value += coef * x ** i % N
...     shares[x] = y_value % N
>>> print(shares[5])
132111105

#endcode
#exercise

Create 7 shares whose threshold is 4

----
>>> from ecc import N
>>> coefficients = [21000000, 11111111, 2222222, 3333333]
>>> # initialize the shares dict
>>> shares = {}  #/
>>> # loop through 1 to 7 inclusive as the x values
>>> for x in range(1, 8):  #/
...    # set the y value to be 0
...    y_value = 0  #/
...    # loop through the coefficients with the loop index
...    for i, coef in enumerate(coefficients):  #/
...        # add the term coef * x^i to the y value
...        y_value += coef * x ** i % N  #/
...    # set the share of x to be the y value mod N
...    shares[x] = y_value % N  #/
>>> # print the last share
>>> print(shares[7])
1350999874

#endexercise
#unittest
frost:PrivatePolynomialTest:test_y_value:
#endunittest
#markdown
# Lagrange Interpolation Polynomial
* For a participant at $x_i$ where $X = \{x_1, x_2, ... x_t\}$
* Goal is a $t-1$ degree polynomial $g_i(x)$ such that: $g_i(x_i)=1$ and $g_i(x_j)=0$ where $j\ne i$
* Note $g_i(x_j)=0$ if $g_i(x)=(x-x_j)h(x)$
* Let $h_i(x)=\prod_{j \ne i}{(x-x_j)}$
* Note $h_i(x)$ is degree $t-1$
* We note $h_i(x_i) = \prod_{j \ne i}{(x_i-x_j)}$
* $g_i(x) = h_i(x)/h_i(x_i)$, $g_i(x_i)=h_i(x_i)/h_i(x_i)=1$ and $g_i(x_j)=0$ where $j\ne i$
#endmarkdown
#code
>>> from ecc import N
>>> # Example LaGrange polynomial with X = {1, 3, 4} for participant 4
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

Create a LaGrange polynomial of degree 4 where $X=\{2,5,8,9\}$ for participant 8 and determine the value at $g(0)$

----
>>> from ecc import N
>>> # define g(x) to be the LaGrange polynomial
>>> def g(x):  #/
...     # define the participants to be [2, 5, 8, 9]
...     participants = [2, 5, 8, 9]  #/
...     # define the place where we want 1 to be x_i
...     x_i = 8  #/
...     # set the product to 1
...     product = 1  #/
...     # loop through the participants x_j
...     for x_j in participants:  #/
...         # if this one is not the place where it's 1, multiply the product
...         if x_j != x_i:  #/
...             # multiply by (x - x_j) / (x_i - x_j), division needs to use field division, that is, multiply by pow(a, -1, N)
...             product *= (x-x_j) * pow(x_i - x_j, -1, N) % N  #/
...     # return the product mod N
...     return product % N
>>> print(g(2), g(5), g(8), g(9), g(0))
0 0 1 0 5

#endexercise
#markdown
# Using LaGrange
* $g_i(x)$ is degree $t-1$ where $g_i(x_i)=1$ and $g_i(x_j)=0$ where $j\ne i$
* Let $h_i(x)=y_ig_i(x)$ notice $h_i(x_i)=y_i$ and $h_i(x_j)=0$ when $j\ne i$
* In other words, $h_i(x)$ is degree $t-1$ and hits the point $(x_i,y_i)$
* Let $h(x)=\sum{h_i(x)}$. We know $h(x_j)=y_j$ because $h_i(x_j)=0$ except $h_j(x_j)=y_j$
* $h(x_i)=y_i \forall x_i \in X$, hitting $t$ points.
* Those points define the same polynomial $h(x)=f(x)$ where $f(x)$ is the dealer's original polynoomial
* Since $f(0)=e$, $h(0)=\sum{h_i(0)}$ meaning we can recover the secret through participant shares and Lagrange Interpolation Polynomials.
#endmarkdown
#code
>>> # example of recovering the secret
>>> from ecc import N
>>> participants = [1, 3, 4]
>>> share_1 = 0xd40aba11bbfdda09607aa1663606e170c57d312fe30be51797b79248fd18ce02
>>> share_3 = 0xb4e3bfec8f3d1404a5eba45ed4052cf1aba29f351d6a73cb3c5437dff82b834
>>> share_4 = 0x4d34c2c9f899ad5db275f0af4d20a1ab43d68d5d6b8be375d69b7fe6b3b7d494
>>> g_1, g_3, g_4 = 1, 1, 1
>>> for x_j in participants:
...     if x_j != 1:
...         g_1 *= (-x_j) * pow(1-x_j, -1, N) % N
...     if x_j != 3:
...         g_3 *= (-x_j) * pow(3-x_j, -1, N) % N
...     if x_j != 4:
...         g_4 *= (-x_j) * pow(4-x_j, -1, N) % N
>>> secret = (g_1*share_1 + g_3*share_3 + g_4*share_4) % N
>>> print(hex(secret))
0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef

#endcode
#exercise

Participants are $X=\{1,3,5,6\}$
Participant 1 has $y_1=1913$
Participant 3 has $y_3=1971$
Participant 5 has $y_5=2009$
Participant 6 has $y_6=2024$

Recover the secret

----
>>> # example of recovering the secret
>>> from ecc import N
>>> from secrets import randbelow
>>> from frost import lagrange_coef
>>> participants = [1, 3, 5, 6]
>>> share_1 = 1913
>>> share_3 = 1971
>>> share_5 = 2009
>>> share_6 = 2024
>>> # initialize the LaGrange values
>>> g_1, g_3, g_5, g_6 = 1, 1, 1, 1  #/
>>> # loop through the participants
>>> for x_j in participants:  #/
...     # g_i = Π(-x_j)/(x_i-x_j) for all i != j
...     if x_j != 1:  #/
...         g_1 *= (-x_j) * pow(1-x_j, -1, N) % N  #/
...     if x_j != 3:  #/
...         g_3 *= (-x_j) * pow(3-x_j, -1, N) % N  #/
...     if x_j != 5:  #/
...         g_5 *= (-x_j) * pow(5-x_j, -1, N) % N  #/
...     if x_j != 6:  #/
...         g_6 *= (-x_j) * pow(6-x_j, -1, N) % N  #/
>>> # calculate the secret by multiplying the value at 0 by the share for each share
>>> secret = (g_1*share_1 + g_3*share_3 + g_5*share_5 + g_6*share_6) % N  #/
>>> # print the secret in hex
>>> print(hex(secret))  #/
0x751

#endexercise
#unittest
frost:LaGrangeTest:test_lagrange:
#endunittest
#markdown
# Dealer Key Generation
* Exactly as Shamir Secret Sharing, a private polynomial $f(x)=e+a_1x+a_2x^2...a_{t-1}x^{t-1}$ where secret is $e$ and $a_i$ is random
* $y$ values at each $x$ is distributed as shares to signers
* We create a public polynomial $F(x)$ which is $f(x)$ multiplied by $G$, $F(x)=f(x)G$ $F(x)=eG+a_1xG+a_2x^2G+...+a_{t-1}x^{t-1}G$
* Note $F(x)=P+xA_1+x^2A_2+...+x^{t-1}A_{t-1}$ where $a_iG=A_i$. Note $F(0)=P$
* $F(x)$ is a public polynomial to the signers
* Each signer once receiving the secret $y_i=f(x_i)$, verifies by checking $y_iG=F(x_i)$
* This $y_iG=F(x_i)=P_i$ is public.
#endmarkdown
#code
>>> # Example of creating 3-of-5 FrostSigners
>>> from frost import Dealer, FrostSigner
>>> dealer = Dealer([21000000, 2000, 3000])
>>> signer_1 = FrostSigner(1, dealer.y_value(1), dealer.public_polynomial)
>>> print(signer_1.point.sec().hex())
02239ebf39e132124de2f7b16de42f8c277d0e7709e2639742348102303243c417

#endcode
#exercise

Make 7 FrostSigners whose threshold is 4.

----
>>> from frost import Dealer, FrostSigner
>>> # use the generate classmethod from Dealer to create a dealer of threshold 4
>>> dealer = Dealer.generate(4)  #/
>>> # make a list of signers whose x's are 1,2,3,...7
>>> signers = [FrostSigner(x, dealer.y_value(x), dealer.public_polynomial) or x in range(1, 8)]  #/
>>> # print the first signer's t
>>> print(signers[0].t)  #/
4

#endexercise
#unittest
frost:DealerTest:test_create_signer:
#endunittest
#markdown
# Partial Sig Verification
* Nonce point is $R=S+bT$ where $b=\mathcal{H}(S||T||P||z)$
* Participant creates the nonce $k_i = l_i + b m_i$
* LaGrange coefficient $c_i = g_i(0)$ and challenge $d=\mathcal{H}(R,P,z)$ come from the signing context
* Partial sig is $s_i = k_i + c_i d y_i$ where $y_i$ is the participant's secret/$y$-value
* If $R$ is odd, participant uses $N-k_i$ for signing because $-R_i=-k_iG$ and $R=\sum{R_i}$
* If $P$ is odd, participant uses $N-e_i$ for signing because $-P_i=-e_iG$ and $P=\sum{c_iP_i}$
#code
>>> # Example Partial Sig Generation
>>> from ecc import N
>>> from frost import Dealer, FrostSigner, FrostCoordinator, lagrange_coef
>>> from helper import int_to_big_endian
>>> msg = b"FROST is awesome!"
>>> dealer = Dealer([21000000, 9999999, 9998888, 8887777])
>>> signers = {x: dealer.create_signer(x) for x in range(1, 7)}
>>> participants = [1, 4, 5, 6]
>>> coor = FrostCoordinator(participants, dealer.public_polynomial)
>>> for x in participants:
...     p = signers[x]
...     nonce_share = p.generate_nonce_share(msg=msg, rand=b'')
...     coor.register_nonce_share(x, nonce_share)
>>> context = coor.create_signing_context(msg)
>>> if context.nonce_point.even:
...     k = signers[1].nonce(context.nonce_coef)
... else:
...     k = N - signers[1].nonce(context.nonce_coef)
>>> if context.group_point.even:
...     e = signers[1].private_key.secret
... else:
...     e = N - signers[1].private_key.secret
>>> c = lagrange_coef(participants, 1)
>>> d = context.challenge
>>> s = (k + c * d * e) % N
>>> print(hex(s))
0x32ec8d7a6b941b80bdf97deb231a9710583e6656e32e69e7aabf00e6e81153fb

#endcode
#markdown
# Partial Sig Verification
* To verify a partial signature, we need from the coordinator: message $z$, nonce point $R$, participants
* We need from the participant nonce point $R_i$ and pubkey $P_i$
* We use these to calculate LaGrange coefficient $c_i=g_i(0)$ and challenge $d=H(R || P || z)$
* $s_i=k_i+c_i d y_i$ so what we check is $s_i G=k_iG+c_i d y_i G=R_i+c_i d P_i$ or $R=s_i G-c_i d P_i$
#endmarkdown
#code
>>> # Example Partial Sig Verification
>>> from ecc import N, G
>>> from frost import Dealer, FrostSigner, FrostCoordinator, lagrange_coef
>>> from helper import int_to_big_endian
>>> msg = b"FROST is awesome!"
>>> dealer = Dealer([21000000, 9999999, 9998888, 8887777])
>>> signers = {x: dealer.create_signer(x) for x in range(1, 7)}
>>> participants = [1, 4, 5, 6]
>>> coor = FrostCoordinator(participants, dealer.public_polynomial)
>>> for x in participants:
...     p = signers[x]
...     nonce_share = p.generate_nonce_share(msg=msg, rand=b'')
...     coor.register_nonce_share(x, nonce_share)
>>> context = coor.create_signing_context(msg)
>>> nonce_public_share = coor.nonce_shares[1]
>>> partial_sig = bytes.fromhex("32ec8d7a6b941b80bdf97deb231a9710583e6656e32e69e7aabf00e6e81153fb")
>>> if context.nonce_point.even:
...     r = nonce_public_share.nonce_point(context.nonce_coef)
... else:
...     r = -1 * nonce_public_share.nonce_point(context.nonce_coef)
>>> if context.group_point.even:
...     p = signers[1].point
... else:
...     p = -1 * signers[1].point
>>> c = lagrange_coef(participants, 1)
>>> d = context.challenge
>>> print(s * G == (r + c * d * p))
True

#endcode
#exercise

Calculate the partial signature for participant 2:

Dealer Coefficients = [12345, 67890]

message: b"Hello World!"

Participant 1's $l$ and $m$: 3000, 4000
Participant 2's $l$ and $m$: 5000, 6000

----
>>> from ecc import N, PrivateKey
>>> from frost import Dealer, FrostSigner, FrostCoordinator, lagrange_coef, NoncePrivateShare
>>> dealer = Dealer([12345, 67890])
>>> msg = b"Hello World!"
>>> signers = {x: dealer.create_signer(x) for x in range(1, 4)}
>>> participants = [1, 2]
>>> coor = FrostCoordinator(participants, dealer.public_polynomial)
>>> participant_1 = signers[1]
>>> participant_2 = signers[2]
>>> nonce_share_1 = NoncePrivateShare(3000, 4000, participant_1.point)
>>> nonce_share_2 = NoncePrivateShare(5000, 6000, participant_2.point)
>>> participant_1.private_nonce_share = nonce_share_1
>>> participant_2.private_nonce_share = nonce_share_2
>>> coor.register_nonce_share(1, nonce_share_1.public_share)
>>> coor.register_nonce_share(2, nonce_share_2.public_share)
>>> # create the signing context
>>> context = coor.create_signing_context(msg)  #/
>>> # determine the second participant's nonce (k_i) from the nonce point's evenness
>>> if context.nonce_point.even:  #/
...     k = participant_2.nonce(context.nonce_coef)  #/
... else:  #/
...     k = N - participant_2.nonce(context.nonce_coef)  #/
>>> # determine the second participant's secret (y_i) from the group point's evenness
>>> if context.group_point.even:  #/
...     y = participant_2.private_key.secret  #/
... else:  #/
...     y = N - participant_2.private_key.secret  #/
>>> # use the lagrange_coef function to get the lagrange coefficient (c_i = g_i(x_i))
>>> c = lagrange_coef(participants, 2)  #/
>>> # use the context's challenge method to get the group challenge (d = H(R||P||z))
>>> d = context.challenge  #/
>>> # now get the partial signature s_i = k + c_i * d * y_i mod N
>>> s = (k + c * d * y) % N  #/
>>> # print the hex of the partial signature
>>> print(hex(s))  #/
0x82f5ea3360c82882a851abf95324d079392fd0c70d7e56a15e0aa8e5c3fb983f

#endexercise
#exercise

Verify the partial signature for participant 2

----
>>> from ecc import N, PrivateKey
>>> from frost import Dealer, FrostSigner, FrostCoordinator, lagrange_coef, NoncePrivateShare
>>> dealer = Dealer([12345, 67890])
>>> msg = b"Hello World!"
>>> signers = {x: dealer.create_signer(x) for x in range(1, 4)}
>>> participants = [1, 2]
>>> coor = FrostCoordinator(participants, dealer.public_polynomial)
>>> participant_1 = signers[1]
>>> participant_2 = signers[2]
>>> raw_nonce_1 = bytes.fromhex("03ed214e8ce499d92a2085e7e6041b4f081c7d29d8770057fc705a131d2918fcdb02609ae8d31e3b290e74483776c1c8dfc2756b87d9635d654eb9e1ca95c228b169")
>>> raw_nonce_2 = bytes.fromhex("02ffe558e388852f0120e46af2d1b370f85854a8eb0841811ece0e3e03d282d57c02d42d696f2c343dc67d80fcd85dbbdb2edef3cac71126625d0cbcacc231a00015")
>>> nonce_share_1 = NoncePublicShare.parse(raw_nonce_1)
>>> nonce_share_2 = NoncePublicShare.parse(raw_nonce_2)
>>> coor.register_nonce_share(1, nonce_share_1)
>>> coor.register_nonce_share(2, nonce_share_2)
>>> # fill in what s equals from the last exercise
>>> s = 0x82f5ea3360c82882a851abf95324d079392fd0c70d7e56a15e0aa8e5c3fb983f  #/
>>> # create the signing context, which should aggregate the points
>>> context = coor.create_signing_context(msg)  #/
>>> # determine the second participant's nonce point (R_i) from the nonce point's evenness
>>> if context.nonce_point.even:  #/
...     r = nonce_share_2.nonce_point(context.nonce_coef)  #/
... else:  #/
...     r = -1 * nonce_share_2.nonce_point(context.nonce_coef)  #/
>>> # determine the second participant's pubkey (P_i) from the group point's evenness
>>> if context.group_point.even:  #/
...     p = participant_2.point  #/
... else:  #/
...     p = -1 * participant_2.point  #/
>>> # get the LaGrange coefficient (c_i) for the second participant
>>> c = lagrange_coef(participants, 2)  #/
>>> # get the challenge for the group (d)
>>> d = context.challenge  #/
>>> # check if s_i * G == R + c * d * P
>>> print(s * G == r + c * d * p)  #/
True

#endexercise
#exercise

Sum the partial signatures, create a Schnorr Signature and verify it using the group point

----
>>> from ecc import N, PrivateKey, SchnorrSignature
>>> from frost import Dealer, FrostSigner, FrostCoordinator, lagrange_coef, NoncePrivateShare
>>> dealer = Dealer([12345, 67890])
>>> msg = b"Hello World!"
>>> signers = {x: dealer.create_signer(x) for x in range(1, 4)}
>>> participants = [1, 2]
>>> coor = FrostCoordinator(participants, dealer.public_polynomial)
>>> participant_1 = signers[1]
>>> participant_2 = signers[2]
>>> raw_nonce_1 = bytes.fromhex("03ed214e8ce499d92a2085e7e6041b4f081c7d29d8770057fc705a131d2918fcdb02609ae8d31e3b290e74483776c1c8dfc2756b87d9635d654eb9e1ca95c228b169")
>>> raw_nonce_2 = bytes.fromhex("02ffe558e388852f0120e46af2d1b370f85854a8eb0841811ece0e3e03d282d57c02d42d696f2c343dc67d80fcd85dbbdb2edef3cac71126625d0cbcacc231a00015")
>>> nonce_share_1 = NoncePublicShare.parse(raw_nonce_1)
>>> nonce_share_2 = NoncePublicShare.parse(raw_nonce_2)
>>> coor.register_nonce_share(1, nonce_share_1)
>>> coor.register_nonce_share(2, nonce_share_2)
>>> context = coor.create_signing_context(msg)
>>> s_1 = 0xa9752dd83e4714576d301274b89ba1042df1c666c4db491b9ba8fb70aaaadc1f
>>> s_2 = 0x82f5ea3360c82882a851abf95324d079392fd0c70d7e56a15e0aa8e5c3fb983f
>>> # sum the two partial sigs and mod by N
>>> s = (s_1 + s_2) % N  #/
>>> # get the nonce point from the context
>>> r = context.nonce_point  #/
>>> # create the Schnorr Signature using the r and the s
>>> sig = SchnorrSignature(r, s)  #/
>>> # check the validity of the schnorr signature using the group point from the context
>>> print(coor.group_point.verify_schnorr(msg, sig))  #/
True

#endexercise
#unittest
frost:PartialSigTest:test_verify:
#endunittest
#unittest
frost:PartialSigTest:test_sign:
#endunittest
#markdown
# FROST Group Point Tweaking
* If the FROST group point is the KeyPath Spend, then there is a tweak $t$
* The group point $P$ and tweak $t$ make the external pubkey $Q=P+tG$
* $Q$ is $x$-only, so that determines $y_i$ negation, not the $P$
* We set $Q$ to be the group point
#endmarkdown
#code
>>> # example of tweaking the FROST group pubkey
>>> from frost import Dealer, FrostCoordinator
>>> dealer = Dealer([21000000, 12345, 67890])
>>> signers = {x: dealer.create_signer(x) for x in range(1, 7)}
>>> merkle_root = b""
>>> participants = [1, 3, 6]
>>> coor = FrostCoordinator(participants, dealer.public_polynomial, merkle_root=merkle_root)
>>> for x in participants:
...     p = signers[x]
...     nonce_share = p.generate_nonce_share(msg=msg, rand=b'')
...     coor.register_nonce_share(x, nonce_share)
>>> context = coor.create_signing_context(msg)
>>> print(context.group_point.sec().hex())
026c45b3bf6705f29302e0f5b911aa5cb84128576f765723ca955c2d6f7916d3a2

#endcode
#markdown
# Partial Sig Aggregation for even/odd $Q$
* For even $Q$: the Schnorr Signature $(R, s+td)$ will validate for the tweaked key $Q$
* For odd $Q$: The Schnorr Signature $(R, s-td)$ will validate for the tweaked key $-Q$
#endmarkdown
#code
>>> # Example FROST KeyPath Spend
>>> from ecc import N, PrivateKey, S256Point
>>> from frost import Dealer, FrostSigner, FrostCoordinator
>>> from script import address_to_script_pubkey
>>> from tx import TxIn, TxOut, Tx
>>> prev_tx = bytes.fromhex("3c78674a5d99932f5236da09f18b18d73c40181b03137ad41e30893bf45a28fa")
>>> prev_index = 0
>>> fee = 500
>>> tx_in = TxIn(prev_tx, prev_index)
>>> target_amount = tx_in.value(network="signet") - fee
>>> target_script = address_to_script_pubkey("tb1q7kn55vf3mmd40gyj46r245lw87dc6us5n50lrg")
>>> tx_out = TxOut(target_amount, target_script)
>>> tx_obj = Tx(1, [tx_in], [tx_out], network="signet", segwit=True)
>>> msg = tx_obj.sig_hash(0)
>>> dealer = Dealer([21000000, 1234567890])
>>> signers = {x: dealer.create_signer(x) for x in range(1, 4)}
>>> merkle_root = b""
>>> participants = [1, 3]
>>> coor = FrostCoordinator(participants, dealer.public_polynomial, merkle_root=merkle_root)
>>> for x in participants:
...     p = signers[x]
...     nonce_share = p.generate_nonce_share(msg=msg, rand=b'')
...     coor.register_nonce_share(x, nonce_share)
>>> me = signers[1]
>>> context = coor.create_signing_context(msg)
>>> my_partial_sig = me.sign(context)
>>> coor.register_partial_sig(1, my_partial_sig)
>>> print(my_partial_sig.hex())
0aebd63a6cd3863a2a104a03ccfb88f958274050380a9e230f288c18fc834177
>>> neighbor_sig = bytes.fromhex("6a8ef5084dcaa656f7ef5ed52867f12a9420425703500dc7d09c3bd3a3d22933")
>>> coor.register_partial_sig(3, neighbor_sig)
>>> s_1 = big_endian_to_int(my_partial_sig)
>>> s_2 = big_endian_to_int(neighbor_sig)
>>> s = (s_1 + s_2) % N
>>> d = context.challenge
>>> t = coor.tweak_amount
>>> if context.group_point.even:
...     s = (s + d * t) % N
... else:
...     s = (s - d * t) % N
>>> r = context.nonce_point
>>> sig = SchnorrSignature(r, s)
>>> print(context.group_point.verify_schnorr(msg, sig))
True
>>> tx_in.finalize_p2tr_keypath(sig.serialize())
>>> print(tx_obj.verify())
True
>>> print(tx_obj.serialize().hex())
01000000000101fa285af43b89301ed47a13031b18403cd7188bf109da36522f93995d4a67783c0000000000ffffffff01ac84010000000000160014f5a74a3131dedb57a092ae86aad3ee3f9b8d7214014062418375ee48647598819439a947b5afe31865bd382ce422540299045a2f474db65f4de60b6b3529966dc7b62cc9c03ce5f6f41571123a47a6cf78d77cc96c6f00000000

#endcode
#unittest
frost:PartialSigTest:test_compute_sig:
#endunittest
"""

FUNCTIONS = """
frost.lagrange
frost.lagrange_coef
frost.recover_secret
frost.Dealer.create_signer
frost.FrostCoordinator.compute_sig
frost.FrostSigner.sign
frost.PrivatePolynomial.y_value
frost.SigningContext.verify
"""
