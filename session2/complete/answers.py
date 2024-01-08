"""
#code
>>> import ecc, op, script, taproot

#endcode
#markdown
# Spending plan
* We have 20,000 sats in this output: 871864d7631024465fc210e553fa9f50e7f0f2359288ad121aa733d65e366995:0
* We want to spend all of it to tb1ptaqplrhnyh3kq85n7dtm5vcpgstt0ev80f4wd8ngeppch4fzu8mquchufq
* 1 input/1 output transaction
#endmarkdown
#code
>>> # Spending from a p2tr
>>> from ecc import PrivateKey, N
>>> from hash import sha256
>>> from helper import big_endian_to_int
>>> from script import address_to_script_pubkey
>>> from tx import Tx, TxIn, TxOut
>>> my_email = b"jimmy@programmingblockchain.com"
>>> my_secret = big_endian_to_int(sha256(my_email))
>>> priv = PrivateKey(my_secret)
>>> prev_tx = bytes.fromhex("871864d7631024465fc210e553fa9f50e7f0f2359288ad121aa733d65e366995")
>>> prev_index = 0
>>> target_address = "tb1ptaqplrhnyh3kq85n7dtm5vcpgstt0ev80f4wd8ngeppch4fzu8mquchufq"
>>> fee = 500
>>> tx_in = TxIn(prev_tx, prev_index)
>>> target_script_pubkey = address_to_script_pubkey(target_address)
>>> target_amount = tx_in.value(network="signet") - fee
>>> tx_out = TxOut(target_amount, target_script_pubkey)
>>> tx_obj = Tx(1, [tx_in], [tx_out], network="signet", segwit=True)
>>> tweaked_secret = (priv.secret + big_endian_to_int(priv.point.tweak())) % N
>>> tweaked_key = PrivateKey(tweaked_secret)
>>> tx_obj.sign_p2tr_keypath(0, tweaked_key)
True
>>> print(tx_obj.serialize().hex())
010000000001019569365ed633a71a12ad889235f2f0e7509ffa53e510c25f46241063d76418870000000000ffffffff012c4c0000000000002251205f401f8ef325e3601e93f357ba33014416b7e5877a6ae69e68c8438bd522e1f601403697a0f0f49a451668b9b0361ec7c3b857299f0f80b8ce8c50e1d3cc87f44382de2b6eeccabe0efda3b1639841c342fce64ba28a2a018d4a9a69f5e7a0d43f6b00000000

#endcode
#exercise

## Checkpoint Exercise

You have been sent 100,000 sats to your address on Signet. Send 40,000 sats back to <code>tb1q7kn55vf3mmd40gyj46r245lw87dc6us5n50lrg</code>, the rest to yourself.

Use <a href="https://mempool.space/signet/tx/push" target="_mempool">Mempool Signet</a> to broadcast your transaction

----

>>> from ecc import PrivateKey
>>> from hash import sha256
>>> from helper import big_endian_to_int
>>> from script import address_to_script_pubkey
>>> from tx import Tx, TxIn, TxOut
>>> my_email = b"jimmy@programmingblockchain.com"  #/my_email = b"<fill this in with your email>"
>>> my_secret = big_endian_to_int(sha256(my_email))
>>> priv = PrivateKey(my_secret)
>>> target_address = "tb1q7kn55vf3mmd40gyj46r245lw87dc6us5n50lrg"
>>> target_amount = 40000
>>> fee = 500
>>> # fill the next two variables from the block explorer
>>> prev_tx = bytes.fromhex("25096348891ff6b120b88c944501791f8809698474569cc994d63dc5bcfe6a37")  #/prev_tx = bytes.fromhex("<fill in from block explorer>")
>>> prev_index = 0  #/prev_index = -1
>>> # create the one input
>>> tx_in = TxIn(prev_tx, prev_index)  #/
>>> # use the address_to_script_pubkey to get the ScriptPubKey
>>> target_script_pubkey = address_to_script_pubkey(target_address)  #/
>>> # create the target output
>>> tx_out_1 = TxOut(target_amount, target_script_pubkey)  #/
>>> # calculate the change amount
>>> change_amount = 100000 - target_amount - fee  #/
>>> # use the private key's point's p2tr_script method to get the change ScriptPubkey
>>> change_script_pubkey = priv.point.p2tr_script()  #/
>>> # create the change output
>>> tx_out_2 = TxOut(change_amount, change_script_pubkey)  #/
>>> # create the transaction
>>> tx_obj = Tx(1, [tx_in], [tx_out_1, tx_out_2], network="signet", segwit=True)  #/
>>> # sign the transaction using the tweaked key and the sign_p2tr_keypath method
>>> tx_obj.sign_p2tr_keypath(0, priv.tweaked_key())  #/
True
>>> # print the serialized hex
>>> print(tx_obj.serialize().hex())  #/
01000000000101376afebcc53dd694c99c5674846909881f790145948cb820b1f61f89486309250000000000ffffffff02409c000000000000160014f5a74a3131dedb57a092ae86aad3ee3f9b8d72146ce80000000000002251204994481c22c21fb6f1362b154b86ec3d04890594b127ae658dda76c6c1cfcf5e014002de2a8a88783937f10742235dfdf6a0f9526f4e8eee9d3d4cd11d5813269a0d1b56b5028b81735dae9d3dd9b9f2fe2193474dba0569cff087c2575f0f8f5b5f00000000

#endexercise
#markdown
# OP_CHECKSIGADD
* Consumes the top three elements: a pubkey, a number, and a signature.
* Valid sig, returns the number+1 to the stack
* Invalid sig, returns the number back to the stack
#endmarkdown
#code
>>> def op_checksigadd_schnorr(stack, tx_obj, input_index):
...     # check to see if there's at least 3 elements
...     if len(stack) < 3:
...         return False
...     # pop off the pubkey
...     pubkey = stack.pop()
...     # pop off the n and do decode_num on it
...     n = decode_num(stack.pop())
...     # pop off the signature
...     sig = stack.pop()
...     # parse the pubkey
...     point = S256Point.parse_xonly(pubkey)
...     # if the signature has 0 length, it is not valid
...     # so put encode_num(n) back on stack and return True
...     if len(sig) == 0:
...         stack.append(encode_num(n))
...         return True
...     # use the get_signature_and_hashtype function on the sig
...     schnorr, hash_type = get_signature_and_hashtype(sig)
...     # get the message from the tx_obj.sig_hash using input index and hash type
...     msg = tx_obj.sig_hash(input_index, hash_type)
...     # verify the Schnorr signature
...     if point.verify_schnorr(msg, schnorr):
...         # if valid, increment the n, encode_num it and push back on stack
...         stack.append(encode_num(n + 1))
...     else:
...         # if invalid, encode_num on n and push back on stack
...         stack.append(encode_num(n))
...     # return True for successful execution
...     return True

#endcode
#markdown
# Example TapScripts
* 1-of-1 (pay-to-pubkey) [pubkey, OP_CHECKSIG]
* 2-of-2 [pubkey A, OP_CHECKSIGVERIFY, pubkey B, OP_CHECKSIG]
* 2-of-3 [pubkey A, OP_CHECKSIG, pubkey B, OP_CHECKSIGADD, pubkey C, OP_CHECKSIGADD, OP_2, OP_EQUAL]
* halvening timelock 1-of-1 [840000, OP_CHECKLOCKTIMEVERIFY, OP_DROP, pubkey, OP_CHECKSIG]
#endmarkdown
#code
>>> # Example TapScripts
>>> from ecc import PrivateKey
>>> from op import encode_minimal_num
>>> from taproot import TapScript
>>> pubkey_a = PrivateKey(11111111).point.xonly()
>>> pubkey_b = PrivateKey(22222222).point.xonly()
>>> pubkey_c = PrivateKey(33333333).point.xonly()
>>> # 1-of-1 (0xAC is OP_CHECKSIG)
>>> tap_script = TapScript([pubkey_a, 0xAC])
>>> print(tap_script)
331a8f6a14e1b41a6b523ddb505fbc0662a6446bd42408692497297d3474aeec OP_CHECKSIG
>>> # 2-of-2 (0xAD is OP_CHECKSIGVERIFY)
>>> tap_script = TapScript([pubkey_a, 0xAD, pubkey_b, 0xAC])
>>> print(tap_script)
331a8f6a14e1b41a6b523ddb505fbc0662a6446bd42408692497297d3474aeec OP_CHECKSIGVERIFY 158a49d62c384c539a453e41a70214cfb85184954ae5c8df4b47eb74d58ff16f OP_CHECKSIG
>>> # 2-of-3 (0xBA is OP_CHECKSIGADD, 0x52 is OP_2, 0x87 is OP_EQUAL)
>>> tap_script = TapScript([pubkey_a, 0xAC, pubkey_b, 0xBA, pubkey_c, 0xBA, 0x52, 0x87])
>>> print(tap_script)
331a8f6a14e1b41a6b523ddb505fbc0662a6446bd42408692497297d3474aeec OP_CHECKSIG 158a49d62c384c539a453e41a70214cfb85184954ae5c8df4b47eb74d58ff16f OP_CHECKSIGADD 582662e8e47df59489d6756615aa3db3fa3bbaa75a424b9c78036265858f5544 OP_CHECKSIGADD OP_2 OP_EQUAL
>>> # halvening timelock 1-of-1 (0xB1 is OP_CLTV, 0x75 is OP_DROP)
>>> tap_script = TapScript([encode_minimal_num(840000), 0xB1, 0x75, pubkey_a, 0xAC])
>>> print(tap_script)
40d10c OP_CHECKLOCKTIMEVERIFY OP_DROP 331a8f6a14e1b41a6b523ddb505fbc0662a6446bd42408692497297d3474aeec OP_CHECKSIG

#endcode
#exercise

Make a TapScript for 4-of-4 using pubkeys from private keys which correspond to 10101, 20202, 30303, 40404

----
>>> from ecc import PrivateKey
>>> from taproot import TapScript
>>> pubkey_1 = PrivateKey(10101).point.xonly()
>>> pubkey_2 = PrivateKey(20202).point.xonly()
>>> pubkey_3 = PrivateKey(30303).point.xonly()
>>> pubkey_4 = PrivateKey(40404).point.xonly()
>>> # create a 4-of-4 tapscript that uses OP_CHECKSIGVERIFY (0xad) and OP_CHECKSIG (0xac)
>>> tap_script = TapScript([pubkey_1, 0xAD, pubkey_2, 0xAD, pubkey_3, 0xAD, pubkey_4, 0xAC])  #/
>>> # print the TapScript
>>> print(tap_script)  #/
134ba4d9c35a66017e9d525a879700a9fb9209a3f43a651fdaf71f3a085a77d3 OP_CHECKSIGVERIFY 027aa71d9cdb31cd8fe037a6f441e624fe478a2deece7affa840312b14e971a4 OP_CHECKSIGVERIFY 165cfd87a31d8fab4431c955b0462804f1ba79b41970ab7e8b0e4e4686f5f8b4 OP_CHECKSIGVERIFY 9e5f5a5c29d33c32185a3dc0a9ccb3e72743744dd869dd40b6265a23fd84a402 OP_CHECKSIG

#endexercise
#markdown
# TapLeaf
* Leaves of the Merkle Tree which contain TapScripts
* Contains TapLeaf Version (<code>0xc0</code>) and TapScript
* Any Leaf can successfully execute its TapScript to spend using the Taproot Script Path
* Hash of a TapLeaf is a Tagged Hash (TapLeaf) of the version + TapScript
#endmarkdown
#code
>>> # Example of making a TapLeaf and calculating the hash
>>> from ecc import PrivateKey
>>> from hash import hash_tapleaf
>>> from taproot import TapScript, TapLeaf
>>> pubkey_a = PrivateKey(11111111).point.xonly()
>>> pubkey_b = PrivateKey(22222222).point.xonly()
>>> tap_script = TapScript([pubkey_a, 0xAD, pubkey_b, 0xAC])
>>> tap_leaf = TapLeaf(tap_script)
>>> h = hash_tapleaf(bytes([tap_leaf.version]) + tap_leaf.tap_script.serialize())
>>> print(h.hex())
d1b3ee8e8c175e5db7e2ff7a87435e8f751d148b77fb1f00e14ff8ffa1c09a40

#endcode
#exercise

Calculate the TapLeaf hash whose TapScript is a 2-of-4 using pubkeys from private keys which correspond to 10101, 20202, 30303, 40404

----
>>> from ecc import PrivateKey
>>> from hash import hash_tapleaf
>>> from helper import int_to_byte
>>> from taproot import TapScript, TapLeaf
>>> pubkey_1 = PrivateKey(10101).point.xonly()
>>> pubkey_2 = PrivateKey(20202).point.xonly()
>>> pubkey_3 = PrivateKey(30303).point.xonly()
>>> pubkey_4 = PrivateKey(40404).point.xonly()
>>> # create a 2-of-4 TapScript that uses OP_CHECKSIG (0xac), OP_CHECKSIGADD (0xba), OP_2 (0x52) and OP_EQUAL (0x87)
>>> tap_script = TapScript([pubkey_1, 0xAC, pubkey_2, 0xBA, pubkey_3, 0xBA, pubkey_4, 0xBA, 0x52, 0x87])  #/
>>> # create the TapLeaf with the TapScript
>>> tap_leaf = TapLeaf(tap_script)  #/
>>> # calculate the hash by using hash_tapleaf on the version and the tap script
>>> h = hash_tapleaf(int_to_byte(tap_leaf.version) + tap_script.serialize())  #/
>>> # print the hash hex
>>> print(h.hex())  #/
0787f5aba506f118a90cefaf00ccfdb2785cf5998d40c3d43ebfaa5b4c6bcb7d

#endexercise
#unittest
taproot:TapRootTest:test_tapleaf_hash:
#endunittest
#markdown
# TapBranch
* Branches of the Merkle Tree
* Contains a left child and a right child.
* Each child is a TapLeaf or TapBranch
* Hash of a TapBranch is a Tagged Hash (TapBranch) of the left hash and right hash, sorted
* Sorting makes verification of the merkle root much easier
#endmarkdown
#code
>>> # Example of making a TapBranch and calculating the hash
>>> from ecc import PrivateKey
>>> from hash import hash_tapbranch
>>> from helper import int_to_byte
>>> from taproot import TapScript, TapLeaf, TapBranch
>>> pubkey_1 = PrivateKey(11111111).point.xonly()
>>> pubkey_2 = PrivateKey(22222222).point.xonly()
>>> tap_script_1 = TapScript([pubkey_1, 0xAC])
>>> tap_script_2 = TapScript([pubkey_2, 0xAC])
>>> tap_leaf_1 = TapLeaf(tap_script_1)
>>> tap_leaf_2 = TapLeaf(tap_script_2)
>>> tap_branch = TapBranch(tap_leaf_1, tap_leaf_2)
>>> left_hash = tap_branch.left.hash()
>>> right_hash = tap_branch.right.hash()
>>> if left_hash > right_hash:
...     h = hash_tapbranch(left_hash + right_hash)
... else:
...     h = hash_tapbranch(right_hash + left_hash)
>>> print(h.hex())
60f57015577d9cc2326d980355bc0896c80a9f94dc692d8738069bc05895634c

#endcode
#exercise

TabBranch Calculation

Calculate the TabBranch hash whose left and right nodes are TapLeafs whose TapScripts are for a 1-of-2 using pubkeys from private keys which correspond to (10101, 20202) for the left, (30303, 40404) for the right

----
>>> from ecc import PrivateKey
>>> from hash import hash_tapbranch
>>> from helper import int_to_byte
>>> from taproot import TapScript, TapLeaf, TapBranch
>>> pubkey_1 = PrivateKey(10101).point.xonly()
>>> pubkey_2 = PrivateKey(20202).point.xonly()
>>> pubkey_3 = PrivateKey(30303).point.xonly()
>>> pubkey_4 = PrivateKey(40404).point.xonly()
>>> # create two 1-of-2 TapScripts [pk_a, 0xac, pk_b, 0xba, 0x51, 0x87]
>>> tap_script_1 = TapScript([pubkey_1, 0xAC, pubkey_2, 0xBA, 0x51, 0x87])  #/
>>> tap_script_2 = TapScript([pubkey_3, 0xAC, pubkey_4, 0xBA, 0x51, 0x87])  #/
>>> # create two TapLeafs with the TapScripts
>>> tap_leaf_1 = TapLeaf(tap_script_1)  #/
>>> tap_leaf_2 = TapLeaf(tap_script_2)  #/
>>> # create the branch
>>> tap_branch = TapBranch(tap_leaf_1, tap_leaf_2)  #/
>>> # get the left and right hashes
>>> left_hash = tap_branch.left.hash()  #/
>>> right_hash = tap_branch.right.hash()  #/
>>> # calculate the hash using the sorted order with hash_tapbranch
>>> if left_hash < right_hash:  #/
...     h = hash_tapbranch(left_hash + right_hash)  #/
... else:  #/
...     h = hash_tapbranch(right_hash + left_hash)  #/
>>> # print the hex of the hash
>>> print(h.hex())  #/
c10993776ad945520c444382b2b6028cdcf2de50aff74f31a32db8c5b5ee72ae

#endexercise
#unittest
taproot:TapRootTest:test_tapbranch_hash:
#endunittest
#markdown
# Computing the Merkle Root
* Merkle Root is the hash of the root element of the Merkle Tree which may be TapLeaf, TapBranch or nothing
* TapLeaf Hash is hash_tapleaf(version + TapScript serialization)
* TapBranch Hash is hash_tapbranch(sorted(left, right))
* It doesn't have to be a hash of anything, just any 32 bytes
* Means addresses can be changed at will
#endmarkdown
#code
>>> # Example of Comupting the Merkle Root
>>> from ecc import PrivateKey
>>> from hash import hash_tapbranch
>>> from helper import int_to_byte
>>> from taproot import TapScript, TapLeaf, TapBranch
>>> pubkey_1 = PrivateKey(11111111).point.xonly()
>>> pubkey_2 = PrivateKey(22222222).point.xonly()
>>> pubkey_3 = PrivateKey(33333333).point.xonly()
>>> tap_script_1 = TapScript([pubkey_1, 0xAC])
>>> tap_script_2 = TapScript([pubkey_2, 0xAC])
>>> tap_script_3 = TapScript([pubkey_3, 0xAC])
>>> tap_leaf_1 = TapLeaf(tap_script_1)
>>> tap_leaf_2 = TapLeaf(tap_script_2)
>>> tap_leaf_3 = TapLeaf(tap_script_3)
>>> tap_branch_1 = TapBranch(tap_leaf_1, tap_leaf_2)
>>> tap_branch_2 = TapBranch(tap_branch_1, tap_leaf_3)
>>> merkle_root = tap_branch_2.hash()
>>> print(merkle_root.hex())
f53fab2e9cf0a458609226b4c42d5c0264700cdf33850c2b1423543a44ad4234

#endcode
#exercise

Calculate the External PubKey for a Taproot output whose internal pubkey has a private key of 90909 and whose Merkle Root is from two TapBranches, each of which is a single signature TapLeaf. The private keys corresponding to the left TapBranch's TapLeafs are 10101 and 20202. The private keys corresponding to the right TapBranch's TapLeafs are 30303 and 40404.

----
>>> from ecc import PrivateKey
>>> from helper import big_endian_to_int
>>> from taproot import TapScript, TapLeaf, TapBranch
>>> p = PrivateKey(90909).point
>>> pubkey_1 = PrivateKey(10101).point.xonly()
>>> pubkey_2 = PrivateKey(20202).point.xonly()
>>> pubkey_3 = PrivateKey(30303).point.xonly()
>>> pubkey_4 = PrivateKey(40404).point.xonly()
>>> tap_script_1 = TapScript([pubkey_1, 0xAC])
>>> tap_script_2 = TapScript([pubkey_2, 0xAC])
>>> tap_script_3 = TapScript([pubkey_3, 0xAC])
>>> tap_script_4 = TapScript([pubkey_4, 0xAC])
>>> # create four TapLeafs with the TapScripts
>>> tap_leaf_1 = TapLeaf(tap_script_1)  #/
>>> tap_leaf_2 = TapLeaf(tap_script_2)  #/
>>> tap_leaf_3 = TapLeaf(tap_script_3)  #/
>>> tap_leaf_4 = TapLeaf(tap_script_4)  #/
>>> # create two TapBranches that have these TapLeafs
>>> tap_branch_1 = TapBranch(tap_leaf_1, tap_leaf_2)  #/
>>> tap_branch_2 = TapBranch(tap_leaf_3, tap_leaf_4)  #/
>>> # create another TapBranch that corresponds to the merkle root and get its hash
>>> m = TapBranch(tap_branch_1, tap_branch_2).hash()  #/
>>> # the external public key (Q) is the internal public key (P) tweaked with the Merkle Root (m)
>>> q = p.tweaked_key(m)  #/
>>> # print the hex of the xonly of the external pubkey
>>> print(q.xonly().hex())  #/
8b9f09cd4a33e62b0c9d086056bbdeb7a218c1e4830291b9be56841b31d94ccb

#endexercise
#markdown
# Control Block Serialization
* Start with TapScript Version (<code>0xc0</code> or <code>0xc1</code>)
* The last bit of the TapScript Version expresses the parity of the external pubkey, which is necessary for batch verification
* $x$-only serialization of the Internal PubKey $P$ (32 bytes)
* Merkle Proof as a list of 32-byte hashes
#endmarkdown
#markdown
# Merkle Proof
* Hash the TapScript version and the TapScript to get the TapLeaf's hash
* Hash the TapLeaf hash and the first Merkle Proof hash sorted
* Hash the current hash and the next Merkle Proof hash sorted, until there are no hashes left
* The result is the Merkle Root $m$. Then compute the tweak: $t=\mathcal{H(P||m)$ where $\mathcal{H}$ is <code>hash_taptweak</code>
* Internal Public Key $P$ is used to compute external public key $Q=P+tG$. If Q matches the UTXO, TapScript is valid.
* Verify the other elements of Witness satisfy the TapScript
#endmarkdown
#code
>>> # Example of Control Block Validation
>>> from ecc import PrivateKey, S256Point
>>> from hash import hash_tapbranch
>>> from taproot import TapScript, TapLeaf, TapBranch
>>> q_xonly = bytes.fromhex("cbe433288ae1eede1f24818f08046d4e647fef808cfbbffc7d10f24a698eecfd")
>>> pubkey_2 = bytes.fromhex("027aa71d9cdb31cd8fe037a6f441e624fe478a2deece7affa840312b14e971a4")
>>> tap_script_2 = TapScript([pubkey_2, 0xAC])
>>> tap_leaf_2 = TapLeaf(tap_script_2)
>>> tap_leaf_1_hash = bytes.fromhex("76f5c1cdfc8b07dc8edca5bef2b4991201c5a0e18b1dbbcfe00ef2295b8f6dff")
>>> tap_leaf_3_hash = bytes.fromhex("5dd270ec91aa5644d907059400edfd98e307a6f1c6fe3a2d1d4550674ff6bc6e")
>>> p = S256Point.parse(bytes.fromhex("407910a4cfa5fe195ad4844b6069489fcb429f27dff811c65e99f7d776e943e5"))
>>> current = tap_leaf_2.hash()
>>> for h in (tap_leaf_1_hash, tap_leaf_3_hash):
...     if h < current:
...         current = hash_tapbranch(h + current)
...     else:
...         current = hash_tapbranch(current + h)
>>> m = current
>>> q = p.tweaked_key(m)
>>> print(q.xonly() == q_xonly)
True
>>> print(p.p2tr_address(m, network="signet"))
tb1pe0jrx2y2u8hdu8eysx8ssprdfej8lmuq3namllrazrey56vwan7s5j2wr8

#endcode
#exercise

Verify the Control Block for the pubkey whose private key is 40404 for the external pubkey from the last exercise

----
>>> from ecc import PrivateKey, S256Point
>>> from helper import big_endian_to_int
>>> from taproot import TapScript, TapLeaf, TapBranch
>>> q_xonly = bytes.fromhex("8b9f09cd4a33e62b0c9d086056bbdeb7a218c1e4830291b9be56841b31d94ccb")
>>> p = PrivateKey(90909).point
>>> hash_1 = bytes.fromhex("22cac0b60bc7344152a8736425efd62532ee4d83e3de473ed82a64383b4e1208")
>>> hash_2 = bytes.fromhex("a41d343d7419b99bfe8e66752fc3c45fd14aa2cc5ef5bf9073ed28dfc60e2e34")
>>> pubkey_4 = bytes.fromhex("9e5f5a5c29d33c32185a3dc0a9ccb3e72743744dd869dd40b6265a23fd84a402")
>>> # create the TapScript and TapLeaf for pubkey 4 using [pubkey, 0xac]
>>> tap_script_4 = TapScript([pubkey_4, 0xAC])  #/
>>> tap_leaf_4 = TapLeaf(tap_script_4)  #/
>>> # set the current hash to the TapLeaf's hash
>>> current = tap_leaf_4.hash()  #/
>>> # loop through hash_1 and hash_2
>>> for h in (hash_1, hash_2):  #/
...     # update current hash to be the hash_tapbranch of h and the current hash, sorted alphabetically
...     if h < current:  #/
...         current = hash_tapbranch(h + current)  #/
...     else:  #/
...         current = hash_tapbranch(current + h)  #/
>>> # set the merkle root m to be the current hash
>>> m = current  #/
>>> # q is p tweaked with m
>>> q = p.tweaked_key(m)  #/
>>> # check to see if the external pubkey's xonly is correct
>>> print(q.xonly() == q_xonly)  #/
True

#endexercise
#unittest
taproot:TapRootTest:test_control_block:
#endunittest
#exercise

Create a Signet P2TR address with these Script Spend conditions:

1. Internal Public Key is <code>cd04c1bf88ca891af152fc57c36523ab59efb16b7ec07caca0cfc4a1f2051d9e</code>
2. Leaf 1 and Leaf 2 make Branch 1, Branch 1 and Leaf 3 make Branch 2, which is the Merkle Root
3. All TapLeaf are single key locked TapScripts (pubkey, OP_CHECKSIG)
4. Leaf 1 uses your xonly pubkey
5. Leaf 2 uses this xonly pubkey: <code>331a8f6a14e1b41a6b523ddb505fbc0662a6446bd42408692497297d3474aeec</code>
6. Leaf 3 uses this xonly pubkey: <code>158a49d62c384c539a453e41a70214cfb85184954ae5c8df4b47eb74d58ff16f</code>

Submit your address at [this link](https://docs.google.com/spreadsheets/d/1BHqFAzgfThrf64q9pCinwTd7FitJrL5Is3HHBR3UyeI/edit?usp=sharing)

----
>>> from ecc import PrivateKey, S256Point
>>> from hash import sha256
>>> from helper import big_endian_to_int
>>> from taproot import TapScript, TapLeaf, TapBranch
>>> my_email = b"jimmy@programmingblockchain.com"  #/my_email = b"<fill this in with your email>"
>>> my_secret = big_endian_to_int(sha256(my_email))
>>> internal_pubkey = S256Point.parse(bytes.fromhex("cd04c1bf88ca891af152fc57c36523ab59efb16b7ec07caca0cfc4a1f2051d9e"))
>>> pubkey_2 = bytes.fromhex("331a8f6a14e1b41a6b523ddb505fbc0662a6446bd42408692497297d3474aeec")
>>> pubkey_3 = bytes.fromhex("158a49d62c384c539a453e41a70214cfb85184954ae5c8df4b47eb74d58ff16f")
>>> # get your xonly pubkey using PrivateKey
>>> my_xonly = PrivateKey(my_secret).point.xonly()  #/
>>> # make the first TapScript and TapLeaf using your xonly and OP_CHECKSIG (0xAC)
>>> tap_script_1 = TapScript([my_xonly, 0xAC])  #/
>>> tap_leaf_1 = TapLeaf(tap_script_1)  #/
>>> # make the second and third TapLeaves using pubkey_2 and pubkey_3 respectively
>>> tap_script_2 = TapScript([pubkey_2, 0xAC])  #/
>>> tap_leaf_2 = TapLeaf(tap_script_2)  #/
>>> tap_script_3 = TapScript([pubkey_3, 0xAC])  #/
>>> tap_leaf_3 = TapLeaf(tap_script_3)  #/
>>> # make a TapBranch with leaf 1 and 2
>>> tap_branch_1 = TapBranch(tap_leaf_1, tap_leaf_2)  #/
>>> # make a TapBranch with branch 1 and leaf 3
>>> tap_branch_2 = TapBranch(tap_branch_1, tap_leaf_3)  #/
>>> # get the hash of this branch, this is the Merkle Root
>>> merkle_root = tap_branch_2.hash()  #/
>>> # print the address using the p2tr_address method of internal_pubkey and specify signet
>>> print(internal_pubkey.p2tr_address(merkle_root, network="signet"))  #/
tb1pxh7kypwsvxnat0z6588pufhx43r2fnqjyn846qj5kx8mgqcamvjsyn5cjg

#endexercise
"""

FUNCTIONS = """
taproot.TapLeaf.hash
taproot.TapBranch.hash
taproot.ControlBlock.merkle_root
taproot.ControlBlock.external_pubkey
"""
