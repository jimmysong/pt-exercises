"""
#exercise

Send yourself the rest of the coins from the output of the previous exercise to the address you just created

Use <a href="https://mempool.space/signet/tx/push" target="_mempool">Mempool Signet</a> to broadcast your transaction

----
>>> from ecc import PrivateKey, S256Point
>>> from hash import sha256
>>> from helper import big_endian_to_int
>>> from script import address_to_script_pubkey
>>> from taproot import TapScript, TapLeaf, TapBranch
>>> from tx import Tx, TxIn, TxOut
>>> my_email = b"jimmy@programmingblockchain.com"  #/my_secret = b"<fill this in with your email>"
>>> my_secret = big_endian_to_int(sha256(my_email))
>>> my_private_key = PrivateKey(my_secret)
>>> prev_tx = bytes.fromhex("69804495c439176266c473081e2f9a3cd298e60a17c8b035fd3070073b865a9c")  #/prev_tx = bytes.fromhex("<fill this in with the tx where you spent last time>")
>>> prev_index = 1
>>> target_address = "tb1pxh7kypwsvxnat0z6588pufhx43r2fnqjyn846qj5kx8mgqcamvjsyn5cjg"  #/target_address = "<fill this in with the address from the last exercise>"
>>> fee = 500
>>> # create a transaction input
>>> tx_in = TxIn(prev_tx, prev_index)  #/
>>> # calculate the target amount
>>> target_amount = tx_in.value(network="signet") - fee  #/
>>> target_script = address_to_script_pubkey(target_address)  #/
>>> # create a transaction output
>>> tx_out = TxOut(target_amount, target_script)  #/
>>> # create a transaction, segwit=True and network="signet"
>>> tx_obj = Tx(1, [tx_in], [tx_out], network="signet", segwit=True)  #/
>>> # calculate the tweaked key from your private key
>>> signing_key = my_private_key.tweaked_key()  #/
>>> # sign the transaction using sign_p2tr_keypath
>>> tx_obj.sign_p2tr_keypath(0, signing_key)  #/
True
>>> # print the serialized hex
>>> print(tx_obj.serialize().hex())  #/
010000000001019c5a863b077030fd35b0c8170ae698d23c9a2f1e0873c466621739c4954480690100000000ffffffff0178e600000000000022512035fd6205d061a7d5bc5aa1ce1e26e6ac46a4cc1224cf5d0254b18fb4031ddb250140b33905727e316ab7fc8c2816761d61af9f1c535cee632a210642f07d619af632c6df51d63099be31e6d12ecd2a465543861eab6e53feb09ccd49288bda1cb8f600000000

#endexercise
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
"""

FUNCTIONS = """
"""
