import socket
import os
import re
import optparse
from cryptoutils import gen_temporal_keypair, generate_master_secret, generate_key_cert
from netutils import *
from base64 import b64decode, b64encode
from Crypto.Util.number import bytes_to_long, long_to_bytes
import time
import ssl


def do_command(sock, masterkey):
    """
    Get a command from the socket, and do it
    :param sock:
    :return:
    """
    cmd = recv_query(sock)
    try:
        if not cmd:
            raise RuntimeError("Invalid command")
        # Format: getpub, dectime, salt
        if cmd[0] == "getpub" and len(cmd) == 3:
            dectime = long(cmd[1])
            salt = long(b64decode(cmd[2]))
            _, pubkey = gen_temporal_keypair(masterkey, dectime, salt)
            if pubkey:
                send_pubkey(pubkey, sock)
            else:
                raise RuntimeError("Invalid arguments")
        elif cmd[0] == "getpriv" and len(cmd) == 3:
            dectime = long(cmd[1])
            salt = long(b64decode(cmd[2]))
            # TODO: A better time check
            if dectime < time.time():
                privkey, _ = gen_temporal_keypair(masterkey, dectime, salt)
                if privkey:
                    send_privkey(privkey, sock)
                else:
                    raise RuntimeError("Invalid arguments")
            else:
                raise RuntimeError("Decryption time has not passed.")
        # Other commands go here
        else:
            raise RuntimeError("Invalid command")
    except RuntimeError, e:
        print "ERROR: ", e.message
        send_error(e.message)
    finally:
        sock.close()


def listen(port, tlsprivkey, tlspubkey, masterkey):
    """
    Listen on port using TLS, accept incoming connections, and spawn a new thread to run commands.
    TODO: Can we bind the server's master secret to the TLS stuff somehow?
    :param port:
    :return:
    """


def parse_opts():
    parser = optparse.OptionParser(usage="Usage: python server.py -k KEYFILE -c CERTFILE -s SECRETFILE [opts]")

    options = optparse.OptionGroup(parser ,"OPTIONS")
    options.add_option("-p", help="Port to listen on", type="int", default=31337, dest="port")
    options.add_option("--setup", help="Do first-run setup", action="store_true", dest="setup")
    options.add_option("-s", "--secret", help="Path to the master secret", dest="secretfile")
    options.add_option("-k", "--key", help="Path to the key", dest="keyfile")
    options.add_option("-c", "--cert", help="Path to the certificate", dest="certfile")
    
    parser.add_option_group(options)

    opts, args = parser.parse_args()
    
    if not opts.keyfile:
        parser.error("key file path required")
    
    if not opts.certfile:
        parser.error("cert file path required")

    if not opts.secretfile:
        parser.error("secret file path required")

    return opts, args



if __name__ == '__main__':
    # TODO: Load master secret, load TLS keys, check clocks
    opts, args = parse_opts()
    if opts.setup:
        generate_master_secret(opts.secretfile)
        generate_key_cert(opts.keyfile,opts.certfile)
    else:
        secretfile=open(opts.secretfile)
        secret=base64.b64decode(secretfile.read())
        s=socket.socket()
        sslSocket=ssl.wrap_socket(s,keyfile=opts.keyfile,certfile=opts.certfile,ssl_version=ssl.PROTOCOL_TLSv1_2)
        listen(opts.port, None, None, None)
