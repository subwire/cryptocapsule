from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.number import bytes_to_long,long_to_bytes
import seccure
import secretsharing
import sha3
import time
import struct
import os
import json
import base64

# the character used for padding--with a block cipher such as AES, the value
# you encrypt must be a multiple of BLOCK_SIZE in length.  This character is
# used to ensure that your value is always a multiple of BLOCK_SIZE
PADDING = '{'

# Checked out safecurves.org for info on this
mycurve = 'brainpoolp256r1'


def encrypt_file(key, in_filename, out_filename, chunksize=64*1024):
    """ Encrypts a file using AES (CBC mode) with the
        given key.
        Based on: http://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto
        key:
            The encryption key - a string that must be
            either 16, 24 or 32 bytes long. Longer keys
            are more secure.

        in_filename:
            Name of the input file

        out_filename:
            If None, '<in_filename>.enc' will be used.

        chunksize:
            Sets the size of the chunk which the function
            uses to read and encrypt the file. Larger chunk
            sizes can be faster for some files and machines.
            chunksize must be divisible by 16.
    """
    iv = Random.get_random_bytes(16)
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filename)

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - len(chunk) % 16)

                outfile.write(encryptor.encrypt(chunk))


def decrypt_file(key, in_filename, out_filename=None, chunksize=24*1024):
    """
    Based on: http://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto
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


def gen_temporal_keypair(masterkey, unixtime, salt):
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
    privkey = sha3.sha3_512(long_to_bytes(masterkey + unixtime + salt)).digest()
    pubkey = seccure.passphrase_to_pubkey(privkey, curve=mycurve)
    return privkey, pubkey


def split_key(key, n, k):
    """
    Split the key into k pieces, such that n of k are required to reproduce the key
    :param key:
    :param n:
    :param k:
    :return: List of n key pieces
    """

    # Re-encode binary key as hex string

    splitter = secretsharing.SecretSharer()
    hexkey = secretsharing.int_to_charset(bytes_to_long(key), splitter.secret_charset)
    pieces = splitter.split_secret(hexkey, n, k)
    return pieces


def join_key(pieces):
    """
    Attempt to recover
    :param pieces: List of pieces
    :return: the key, or None on failure
    """
    try:
        joiner = secretsharing.SecretSharer()
        hexkey = joiner.recover_secret(pieces)
        return long_to_bytes(secretsharing.charset_to_int(hexkey, joiner.secret_charset))
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


def get_pubkey(server, dectime, salt):
    """
    Contact the server, and get its EC key
    :param server:
    :return: Return pubkey
    """

    # TODO: IMPLEMENT THIS

    fake_masterkey = "blahblahblah"
    privkey, pubkey = gen_temporal_keypair(bytes_to_long(fake_masterkey),dectime,salt)
    return pubkey


def get_privkey(server, dectime, salt):
    """
    Contact the server, and get its EC key
    :param server:
    :return: Return privkey, or None on failure
    """

    # TODO: IMPLEMENT THIS

    fake_masterkey = "blahblahblah"
    if dectime < time.time():
        privkey, pubkey = gen_temporal_keypair(bytes_to_long(fake_masterkey),dectime,salt)
        return privkey
    return None


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
    metadata = {}
    # Now, go get some EC keys
    selector = select_server(serverlist)
    while len(eckeys) != k:
        # Pick a server
        try:
            server = selector.next()
        except StopIteration:
            print "Could not get enough EC keys!"
            return None
        pubkey = get_pubkey(server, dectime, salt)
        if pubkey is None:
            print "Getting temporal public key from server " + server + " failed. Trying another..."
        else:
            eckeys.append((server, pubkey))
    randkey = Random.new().read(16)
    # Split the key
    pieces = split_key(randkey, n, k)
    enc_keybits = []
    # Encrypt the pieces with EC keys
    for (piece,eckey) in zip(pieces, eckeys):
        enc_keybits.append((eckey[0], base64.b64encode(eckey[1].encrypt(piece))))
    print repr(randkey)
    # Encrypt the file
    encrypt_file(randkey, filename, outfile)

    # Wrte out the metadata
    metadata['dectime'] = dectime
    metadata['salt'] = salt
    metadata['n'] = n
    metadata['k'] = k
    metadata['locks'] = enc_keybits
    with open(outfile + ".ccapsule", "w+") as mdf:

            json.dump(metadata, mdf)


def decrypt(infile, metadatafile, outfile):
    """
    Decrypt a file, given the cryptoblob and metadata
    :param infile: The cryptoblob
    :param metadata: The CryptoCapsule metadata
    :param outfile: The decrypted file
    :return: n/a
    """
    metadata = {}
    # Load the metadata
    with open(metadatafile, "r") as mdf:
        try:
            metadata = json.load(mdf)
        except:
            print "Error loading metadata!"
            return

    # Try to get private keys and decrypt key pieces
    pieces = []
    while len(pieces) < metadata['n']:
        try:
            server, blob = metadata['locks'].pop()
        except:
            print "Unable to gather enough keys to decrypt!"
            return
        privkey = get_privkey(server,metadata['dectime'],metadata['salt'])
        if not privkey:
            print "Error getting private key from " + server
            continue
        pieces.append(seccure.decrypt(base64.b64decode(blob), privkey, curve=mycurve))

    # Now try to recover the key
    symkey = join_key(pieces)
    print repr(symkey)
    if not symkey:
        print "Unable to recover key!"
        return

    # Do the decryption
    decrypt_file(symkey,infile,outfile)