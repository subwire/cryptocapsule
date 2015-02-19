#!/usr/bin/python

import optparse
import os
import sys
from cryptoutils import encrypt, decrypt


def parse_opts():
    parser = optparse.OptionParser(usage="Usage: ccapsule [opts] infile outfile")
    commands = optparse.OptionGroup(parser, "COMMANDS")
    commands.add_option("-e", "--encrypt", help="Encrypt a file", action="store_true", dest="encrypt")
    commands.add_option("-d", "--decrypt", help="Decrypt a file", action="store_true", dest="decrypt")
    options = optparse.OptionGroup(parser,"OPTIONS")
    options.add_option("-n", help="Minimum number of key pieces needed for recovery", type="int", default=10,
                       dest="n")
    options.add_option("-k", help="Total number of key pieces", type="int", default=20, dest="k")
    options.add_option("-t", "--time", help="UNIX time after which the file's keys will be available",
                       type="int", dest="time")
    options.add_option("-m", "--metadata", help="The metadadta file needed to decrypt a CryptoCapsule.  If not "
                                                "specified, it may be automatically found")
    options.add_option("-l", "--server-list", help="Specify an alternative server list", dest="serverlist")
    opts, args = parser.parse_args()
    if not opts.encrypt and not opts.decrypt:
        parser.error("You must specify either -d or -e")
    if not opts.time:
        parser.error("You must specify a time with -t")
    if len(args) < 2:
        parser.error("Please specify an input file and an output file")
    if opts.decrypt and not opts.metadata:
        if os.path.exists(args[0] + ".ccapsule"):
            opts.metadata = args[0] + ".ccapsule"
        else:
            parser.error("You must specify a metadata file with -m")

    return opts, args


def load_serverlist(filename):
    serverlist = []
    with open(filename,"r") as f:
        for line in f.readlines():
            if not line.strip():
                continue
            serverlist.append(line)
    return serverlist


if __name__ == '__main__':
    opts, args = parse_opts()
    if not opts.serverlist:
        # TODO: When the server is implemented, remove this
        serverlist = []
        for x in range(0,opts.k):
            serverlist.append('localhost')
    else:
        serverlist = load_serverlist(opts.serverlist)
    if opts.encrypt:
        encrypt(args[0], args[1], opts.time, opts.n, opts.k, serverlist)
    elif opts.decrypt:
        decrypt(args[0],opts.metadata, args[1])
