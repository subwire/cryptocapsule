from netutils import *
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.number import bytes_to_long,long_to_bytes
import seccure
import secretsharing
import sha3
import time
import struct
import os

# the character used for padding--with a block cipher such as AES, the value
# you encrypt must be a multiple of BLOCK_SIZE in length.  This character is
# used to ensure that your value is always a multiple of BLOCK_SIZE
PADDING = '{'

# Checked out safecurves.org for info on this
mycurve = 'brainpoolp256r1'

def encrypt_file(infile,outfile,chunksize=24*1024):
    """
    Encrypt file with a random key
    :param infile: The filename of the thing to encrypt
    :param outfile: The output filename
    :param chunksize: The size of chunks read from disk, in bytes (merely an IO optimization thing)
    :return: The key used.

    """
    try:
        with open(infile,"rb") as inf:
            # TODO: My memory says there's something not right about the way in which I get the
            # size here...  We should be using that file handle
            filesize = os.path.getsize(in_filename)
            with open(outfile,"wb+") as outf:
                # Get some random bits
                # TODO: Should we get a new Random generator object, or reuse it?
                siv = Random.new().read(AES.block_size)
                randkey = Random.new().read(16)
                cipher = AES.new(randkey, AES.MODE_CFB, siv)

                # Read the file a block at a time, encrypt, write
                outf.write(struct.pack('<Q', filesize))
                outf.write(iv)

                while True:
                    chunk = infile.read(chunksize)
                    if len(chunk) == 0:
                        break
                    elif len(chunk) % 16 != 0:
                        chunk += PADDING * (16 - len(chunk) % 16)

                    outf.write(cipher.encrypt(chunk))

                return randkey
    except IOError, e:
        print "Error encrypting file!"
        return None


def decrypt_file(key, in_filename, out_filename=None, chunksize=24*1024):
    """
    :param in_filename: Input file
    :param out_filename: Output file
    :param chunksize: Size read from disk in chunks
    :return: n/a
    """
    try:
        with open(in_filename, 'rb') as infile:
            origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
            iv = infile.read(16)
            decryptor = AES.new(key, AES.MODE_CBC, iv)

            with open(out_filename, 'wb') as outfile:
                while True:
                    chunk = infile.read(chunksize)
                    if len(chunk) == 0:
                        break
                    outfile.write(decryptor.decrypt(chunk))
                # This lops off the padding
                outfile.truncate(origsize)
    except IOError, e:
        print "Error decrypting file"
    return


def gen_temporal_keypair(masterkey,unixtime,salt):
    """
    Generate a "temporal keypair". that is derrived from a system's global secret "key", the desired 64-bit UNIX time
    and the user-provided salt.
    :param masterkey: The system global key.  1024 bits
    :param unixtime: The time to generate for
    :param salt: The user-provided salt
    :return: An EC keypair privkey,pubkey
    """
    # Smoosh the stuff together
    # TODO: is this right?

    # In EC, the passphrase IS the privkey, but if we just use it plain, we will give away the masterkey
    # So we hash it all up first.
    privkey = sha3.sha3_512(masterkey + unixtime + salt)
    pubkey = seccure.passphrase_to_pubkey(privkey,curve=mycurve)
    return privkey, pubkey

def split_key(key,n,k):
    """
    Split the key into k pieces, such that n of k are required to reproduce the key
    :param key:
    :param n:
    :param k:
    :return: List of n key pieces
    """
    splitter = secretsharing.SecretSharer()
    pieces = splitter.split_secret(key, n, k)
    return pieces


def join_key(pieces):
    """
    Attempt to recover
    :param pieces: List of pieces
    :return: the key, or None on failure
    """
    try:
        joiner = secretsharing.SecretSharer()
        return joiner.recover_secret(pieces)
    except:
        print "Error recovering key!"
        return None


def select_server(serverlist):
    """
    A generator that returns the next server to try.
    TODO: Make this prefer a geographic distribution
    :param serverlist:
    :return:
    """
    # This is a stub
    for server in serverlist:
        yield server



def encrypt(filename,outfile,dectime,n,k,serverlist):
    """
    The main encrypt function.  Given a filename, outfile, n, k, serverlist:
     1. Generate a hash
     2. Gather sufficient EC pubkeys from servers
     2.
    :param filename: The file to encrypt
    :param outfile: The file to write to
    :param dectime: The time for the file to be decryptable
    :param n: Minimum number of servers needed to decrypt
    :param k: Total number of servers
    :param serverlist: The list of servers to pick from
    :return: keypieces, salt
    """
    # First, this file needs a salt
    salt = bytes_to_long(Random.get_random_bytes(128))
    eckeys = []
    # Now, go get some EC keys
    while len(eckeys) != k:
        # Pick a server
        server = select_server(serverlist)
        if server is None:
            print "Could not get enough EC keys!"
            return None
        try:
            # Try to get its key
            get_pubkey(server, dectime, salt)
        except;
            print "Getting key from server " + server + " failed. Trying another..."
    # Encrypt the file
    symkey = encrypt_file(filename, outfile)

    # Split the key
    pieces = split_key(symkey,n,k)

    enc_keybits = []

    # Encrypt the pieces with EC keys
    for (piece,eckey) in zip(pieces, eckeys):
        enc_keybits.append(seccure.encrypt(piece,eckey,curve=mycurve))

    # Prepend all that stuff to the file
    # TODO: This

    return enc_keybits, salt


def get_pubkey(server, dectime, salt):
    """
    Contact the server, and get its EC key
    :param server:
    :return: Return pubkey
    """

    # TODO: IMPLEMENT THIS

    fake_masterkey = "blahblahblah"
    _,pubkey = gen_temporal_keypair(bytes_to_long(fake_masterkey),dectime,salt)
    return pubkey


def get_privkey(server, dectime, salt):
    """
    Contact the server, and get its EC key
    :param server:
    :return: Return pubkey
    """

    # TODO: IMPLEMENT THIS

    fake_masterkey = "blahblahblah"
    if dectime < time.time():
        privkey,_ gen_temporal_keypair(bytes_to_long(fake_masterkey),dectime,salt)
        return privkey
    return None
