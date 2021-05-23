import base64
from cryptography.hazmat.primitives import hashes 
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Hash import HMAC


def b64(msg):
    # base64 encoding helper function
    return base64.encodebytes(msg).decode("utf-8").strip()


def send(client1, client2, msg):
    #helper function to update ratchets on send
    client1.send(client2, msg)

    if client1.is_initializer:
        client1.init_send(client2.DHratchet.key.public_key())
        client2.init_recv(client1.DHratchet.key.public_key())
        client2.init_send(client1.DHratchet.key.public_key())
        client1.init_recv(client2.DHratchet.key.public_key())
    else:
        client2.init_send(client1.DHratchet.key.public_key())
        client1.init_recv(client2.DHratchet.key.public_key())
        client1.init_send(client2.DHratchet.key.public_key())
        client2.init_recv(client1.DHratchet.key.public_key())


def hkdf(inp, length):
    # use HKDF on an input to derive a key
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=b"",
        info=b"",
        backend=default_backend(),
    )
    return hkdf.derive(inp)


def pad(msg):
    # pkcs7 padding
    num = 16 - (len(msg) % 16)
    return msg + bytes([num] * num)


def unpad(msg):
    # remove pkcs7 padding
    return msg[: -msg[-1]]


# The Diffie Hellman Ratchet
class DHRatchet(object):
    def __init__(self, state):
        self.key = X25519PrivateKey.generate()
        self.state = state

    def next(self, public_key):
        # perform a DH key exchange with public_key
        if self.state < 2:
            output = self.key.exchange(public_key)
            self.state += 1
            return output
        else:
            self.state = 0
            self.key = X25519PrivateKey.generate()
            output = self.key.exchange(public_key)
            self.state += 1
            return output

# The Symmetric Ratchet
class SymmRatchet(object):
    def __init__(self, key):
        self.state = key

    def next(self, inp=b""):
        # turn the ratchet, changing the state and yielding a new key and IV
        output = hkdf(self.state + inp, 80)
        self.state = output[:32]
        outkey, iv = output[32:64], output[64:]
        return outkey, iv

# The Client Class, e.g. Alice/Bob
class Client(object):
    def __init__(self, name, is_initializer):
        self.sendCounter = 0
        self.receiveCounter = 0
        self.name = name
        self.is_initializer = is_initializer
        # generate keys
        self.SPK = X25519PrivateKey.generate()
        self.OPK = X25519PrivateKey.generate()
        self.IK = X25519PrivateKey.generate()
        self.EK = X25519PrivateKey.generate()
        # Different initial DHRatchet states, just an implementation quirk.
        if self.is_initializer:
            self.DHratchet = DHRatchet(0)
        else:
            self.DHratchet = DHRatchet(1)

    def clone(self):
        # create a clone of current client
        clone = Client(self.name, self.is_initializer)
        clone.sendCounter = self.sendCounter
        clone.receiveCounter = self.receiveCounter
        clone.name = self.name
        clone.is_initializer = self.is_initializer
        clone.SPK = self.SPK
        clone.OPK = self.OPK
        clone.IK = self.IK
        clone.EK = self.EK
        clone.DHratchet = self.DHratchet
        clone.sk = self.sk
        clone.epochKey = self.epochKey
        clone.root_ratchet = self.root_ratchet
        clone.send_ratchet = self.send_ratchet
        clone.recv_ratchet = self.recv_ratchet
        return clone

    def x3dh(self, client):
        # perform the triple Diffie Hellman exchange (X3DH)

        # initializing the key exchange
        if self.is_initializer:
            dh1 = self.IK.exchange(client.SPK.public_key())
            dh2 = self.EK.exchange(client.IK.public_key())
            dh3 = self.EK.exchange(client.SPK.public_key())
            dh4 = self.EK.exchange(client.OPK.public_key())
            # the shared key is KDF(DH1||DH2||DH3||DH4)
            self.sk = hkdf(dh1 + dh2 + dh3 + dh4, 32)
            self.epochKey = SHA256.new(self.sk)
        # not the initializer, i.e. you have come online second
        else:
            dh1 = self.SPK.exchange(client.IK.public_key())
            dh2 = self.IK.exchange(client.EK.public_key())
            dh3 = self.SPK.exchange(client.EK.public_key())
            dh4 = self.OPK.exchange(client.EK.public_key())
            # the shared key is KDF(DH1||DH2||DH3||DH4)
            self.sk = hkdf(dh1 + dh2 + dh3 + dh4, 32)
            self.epochKey = SHA256.new(self.sk)
    
    #initialize/update KDF chains
    def init_root(self):
        self.root_ratchet = SymmRatchet(self.sk)

    def init_send(self, client_public_key):
        inp = self.DHratchet.next(client_public_key)
        self.send_ratchet = SymmRatchet(self.root_ratchet.next(inp)[0])

    def init_recv(self, client_public_key):
        inp = self.DHratchet.next(client_public_key)
        self.recv_ratchet = SymmRatchet(self.root_ratchet.next(inp)[0])

    # send a message
    def send(self, client, msg):
        self.sendCounter += 1
        byteCounter = str(self.sendCounter).encode()
        key, iv = self.send_ratchet.next()
        macCipher = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg + byteCounter))
        cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg))
        print(f"[{self.name}]\tSending ciphertext to {client.name}:", b64(cipher))
        mac = HMAC.new(self.epochKey.digest(), macCipher)
        client.recv(cipher, self.sendCounter, mac, macCipher)

    #recieve a message
    def recv(self, cipher, count, mac, macCipher):
        testMac = HMAC.new(self.epochKey.digest(), macCipher)
        if count > self.receiveCounter and mac.digest() == testMac.digest():
            self.receiveCounter += 1
            key, iv = self.recv_ratchet.next()
            msg = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(cipher))
            print(f"[{self.name}]\tDecrypted message:", msg)
        else:
            print("CLONE DETECTED")


alice = Client("Alice", True)
bob = Client("Bob", False)

# Alice performs an X3DH while Bob is offline, using his uploaded keys
alice.x3dh(bob)

# Bob comes online and performs an X3DH using Alice's public keys
bob.x3dh(alice)

# Initialize their symmetric ratchets
alice.init_root()
bob.init_root()

alice.init_send(bob.DHratchet.key.public_key())
bob.init_recv(alice.DHratchet.key.public_key())
bob.init_send(alice.DHratchet.key.public_key())
alice.init_recv(bob.DHratchet.key.public_key())

# Print out the matching pairs
"""print("[Alice]\tsend ratchet:", list(map(b64, alice.send_ratchet.next())))
print("[Bob]\trecv ratchet:", list(map(b64, bob.recv_ratchet.next())))
print("[Alice]\trecv ratchet:", list(map(b64, alice.recv_ratchet.next())))
print("[Bob]\tsend ratchet:", list(map(b64, bob.send_ratchet.next())))"""

print("***** NO CLONE *****")
send(alice, bob, b"Hello Bob!")
send(bob, alice, b"Hello to you too, Alice!")

bob_clone_no_state_loss = bob.clone()
print() 
print("***** BOB CLONED - NO STATE LOSS *****") 
send(bob_clone_no_state_loss, alice, b"test bob_clone->alice message")
send(bob_clone_no_state_loss, alice, b"test bob_clone->alice message")
# this will cause clone detection, since the counters will be out of sync
send(bob, alice, b"test bob->alice message")

# now the clone pretends to have undergone total state loss, so Alice and the clone reinitialize
bob_clone_state_loss = Client("Bob", False)
alice.sendCounter = 0
alice.receiveCounter = 0
alice.x3dh(bob_clone_state_loss)
bob_clone_state_loss.x3dh(alice)

alice.init_root()
bob_clone_state_loss.init_root()

alice.init_send(bob_clone_state_loss.DHratchet.key.public_key())
bob_clone_state_loss.init_recv(alice.DHratchet.key.public_key())
bob_clone_state_loss.init_send(alice.DHratchet.key.public_key())
alice.init_recv(bob_clone_state_loss.DHratchet.key.public_key())

# The clone and alice can now have a conversation without alice knowing bob has been cloned
print() 
print("***** BOB CLONED - TOTAL STATE LOSS *****") 
send(alice, bob_clone_state_loss, b"Hello Bob!")
send(bob_clone_state_loss, alice, b"Hello to you too, Alice!")
send(alice, bob_clone_state_loss, b"test alice->bob_clone message")
send(alice, bob_clone_state_loss, b"test alice->bob_clone message")
send(alice, bob_clone_state_loss, b"test alice->bob_clone message")
send(bob_clone_state_loss, alice, b"test bob_clone->alice message")
send(bob_clone_state_loss, alice, b"test bob_clone->alice message")
send(bob_clone_state_loss, alice, b"test bob_clone->alice message")

# However, once the original Bob comes back online, alice will detect a clone
send(bob, alice, b"test bob->alice message")
