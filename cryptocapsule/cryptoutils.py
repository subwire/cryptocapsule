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
import OpenSSL
import datetime

# the character used for padding--with a block cipher such as AES, the value
# you encrypt must be a multiple of BLOCK_SIZE in length.  This character is
# used to ensure that your value is always a multiple of BLOCK_SIZE
PADDING = '{'

# Length of the random salt
SALTLEN = 64

# Length of the AES key
AESLEN = 16

# Checked out safecurves.org for info on this
mycurve = 'brainpoolp256r1'

def ecc_encrypt_string(strng, pubkey):
    return seccure.encrypt(strng, pubkey, pk_format=seccure.SER_BINARY, curve=mycurve)

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
    :param key: the key, in bytes
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
    :param masterkey: The system global key.  1024 bits BYTE STRING
    :param unixtime: The time to generate for, as a LONG
    :param salt: The user-provided salt 1024 BYTE STRING
    :return: An EC keypair privkey,pubkey as BYTE STRINGS
    """
    # Smoosh the stuff together
    # TODO: is this right?

    # In EC, the passphrase IS the privkey, but if we just use it plain, we will give away the masterkey
    # So we hash it all up first.
    mk = bytes_to_long(masterkey)
    st = bytes_to_long(salt)
    privkey = sha3.sha3_512(long_to_bytes(mk + unixtime + st)).digest()
    pubkey = seccure.passphrase_to_pubkey(privkey, curve=mycurve)
    return privkey, pubkey


def generate_master_secret(secretfile):
    with open(secretfile,"w") as f:
        secret = Random.new().read(SALTLEN)
        f.write(base64.b64encode(secret))

def generate_key_cert(keyfile,certfile):
    with open(keyfile,"w") as f:
        key=OpenSSL.crypto.PKey()
        key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
        f.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key))
    with open(certfile,"w") as f:
        cert = OpenSSL.crypto.X509()
        subject = cert.get_subject()
        subject.CN = b"localhost"
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(60 * 60 * 24 * 365 * 100)
        cert.set_pubkey(key)
        cert.sign(key, b"sha1")
        f.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))
        

def split_key(key, n, k):
    """
    Split the key into k pieces, such that n of k are required to reproduce the key
    :param key: Key, as a BYTE STRING
    :param n: minimum recovery pieces, as an INT
    :param k: Total pieces, as an INT
    :return: List of n key pieces as a list of STRINGS
    """

    if n < 2 or k < 2:
        return key
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

