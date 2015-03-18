#!/usr/bin/python

import optparse
import os
import sys
from cryptoutils import *
from netutils import get_privkey, get_pubkey, select_server


def encrypt(filename,outfile,dectime,n,k,serverlist, sslnoverify=False):
    """
    The main encrypt function.  Given a filename, outfile, n, k, serverlist:
     1. Generate a salt of 128 random bytes
     2. Gather sufficient EC pubkeys from servers
     3. Generate a random symmetric key
     4. Encrypt the file with the random symmetric key
     5. Split the key into (n,k) pieces
     6. Pack up all the metadata, and write it out

    :param filename: The file to encrypt
    :param outfile: The file to write to
    :param dectime: The time for the file to be decryptable
    :param n: Minimum number of servers needed to decrypt
    :param k: Total number of servers
    :param serverlist: The list of servers to pick from
    :return: keypieces, salt
    """
    # First, this file needs a random key
    randkey = Random.new().read(AESLEN)
    # And a random salt
    # TODO: Are we doing these in the right order to minimize crazy RNG prediction stuff?
    salt = Random.new().read(SALTLEN)
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
        pubkey = get_pubkey(server, dectime, salt, sslnoverify=sslnoverify)
        if pubkey is None:
            print "Getting temporal public key from server " + server + " failed. Trying another..."
        else:
            eckeys.append((server, pubkey))
    # Split the key
    pieces = split_key(randkey, n, k)
    enc_keybits = []
    # Encrypt the pieces with EC keys
    # FYI: eckey[0] is the server's hostname, and eckey[1] is the actual EC temporal public key
    for (piece, eckey) in zip(pieces, eckeys):
        enc_piece = ecc_encrypt_string(piece, eckey[1])
        enc_keybits.append((eckey[0], base64.b64encode(enc_piece)))
    # Encrypt the file
    print "Encrypting file..."
    encrypt_file(randkey, filename, outfile)
    print "Saving locks..."
    # Wrte out the metadata
    metadata['dectime'] = dectime
    metadata['salt'] = base64.b64encode(salt)
    metadata['n'] = n
    metadata['k'] = k
    metadata['locks'] = enc_keybits
    with open(outfile + ".ccapsule", "w+") as mdf:

            json.dump(metadata, mdf)


def decrypt(infile, metadatafile, outfile, sslnoverify=False):
    """
    Decrypt a file, given the cryptoblob and metadata

    1. Attempt to fetch temporal private keys from servers
    2. If enough have been gathered, decrypt key pieces, re-assemble symmetric key
    3. Decrypt file

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
    salt = base64.b64decode(metadata['salt'])
    dectime = metadata['dectime']
    # Try to get private keys and decrypt key pieces
    pieces = []
    while len(pieces) < metadata['n']:
        try:
            server, blob = metadata['locks'].pop()
        except:
            print "Unable to gather enough keys to decrypt!"
            return
        privkey = get_privkey(server, dectime, salt, sslnoverify=sslnoverify)
        if not privkey:
            print "Error getting private key from " + server
            continue
        pieces.append(seccure.decrypt(base64.b64decode(blob), privkey, curve=mycurve))

    # Now try to recover the key
    if metadata['n'] == 1 and metadata['k'] == 1:
        symkey = pieces[0]
    else:
        symkey = join_key(pieces)
    if not symkey:
        print "Unable to recover key!"
        return

    # Do the decryption
    decrypt_file(symkey, infile, outfile)


def parse_opts():
    parser = optparse.OptionParser(usage="Usage: ccapsule <-e|-d> [opts] infile outfile\n" + 
					 "Example: ccapsule -e -t 1426635888 -l mylist.txt -n 5 -k 10 deathstarplans.txt deathstarplans.enc\n" +
                                         "         ccapsule -d deathstarplans.enc")
    commands = optparse.OptionGroup(parser, "COMMANDS")
    commands.add_option("-e", "--encrypt", help="Encrypt a file", action="store_true", dest="encrypt")
    commands.add_option("-d", "--decrypt", help="Decrypt a file", action="store_true", dest="decrypt")
    parser.add_option_group(commands)

    options = optparse.OptionGroup(parser,"OPTIONS")
    options.add_option("-n", help="Minimum number of key pieces needed for recovery", type="int", default=10,
                       dest="n")
    options.add_option("-k", help="Total number of key pieces", type="int", default=20, dest="k")
    options.add_option("-t", "--time", help="UNIX time after which the file's keys will be available",
                       type="int", dest="time")
    options.add_option("-m", "--metadata", help="The metadadta file needed to decrypt a CryptoCapsule.  If not "
                                                "specified, it may be automatically found")
    options.add_option("-l", "--server-list", help="Specify an alternative server list.  List should be a return-separated list of hostnames or IP addresses", dest="serverlist")
    options.add_option("-S", "--disable-ssl-verification", help="Don't verify SSL certs of remote servers",
                       action="store_true", dest="sslnoverify")
    parser.add_option_group(options)

    opts, args = parser.parse_args()
    if not opts.encrypt and not opts.decrypt:
        parser.error("You must specify either -d or -e")
    if opts.encrypt and not opts.time:
        parser.error("You must specify a time with -t")
    if opts.n > opts.k:
        parser.error("N must be less than or equal to K")
    if len(args) < 2:
        parser.error("Please specify an input file and an output file")
    if opts.decrypt and not opts.metadata:
        if os.path.exists(args[0] + ".ccapsule"):
            opts.metadata = args[0] + ".ccapsule"
        else:
            parser.error("You must specify a metadata file with -m")
    if opts.encrypt and not opts.serverlist:
        parser.error("You must specify a server list.")
    return opts, args


def load_serverlist(filename):
    serverlist = []
    with open(filename, "r") as f:
        for line in f.readlines():
            if not line.strip():
                continue
            serverlist.append(line.strip())
    return serverlist


if __name__ == '__main__':
    opts, args = parse_opts()
    if opts.encrypt:
        # Load the server list
        server_list = load_serverlist(opts.serverlist)
        encrypt(args[0], args[1], opts.time, opts.n, opts.k, server_list, sslnoverify=opts.sslnoverify)
    elif opts.decrypt:
        decrypt(args[0], opts.metadata, args[1], sslnoverify=opts.sslnoverify)
