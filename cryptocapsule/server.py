import socket
import os
import sys
import re
import optparse
from cryptoutils import gen_temporal_keypair, generate_master_secret, generate_key_cert
from netutils import *
from base64 import b64decode, b64encode
import time
import ssl
import threading


def do_command(sock, masterkey):
    """
    Get a command from the socket, and do it
    :param sock:
    :return:
    """
    cmd = recv_query(sock)
    print "Got command: " + repr(cmd)
    try:
        if not cmd:
            raise RuntimeError("Invalid command")
        # Format: getpub, dectime, salt
        if cmd[0] == "GETPUB:" and len(cmd) == 3:
            dectime = long(cmd[1])
            salt = b64decode(cmd[2])
            _, pubkey = gen_temporal_keypair(masterkey, dectime, salt)
            if pubkey:
                print "Sending public key to client"
                send_pubkey(pubkey.to_bytes(), sock)
            else:
                print "Got weird stuff from client"
                raise RuntimeError("Invalid arguments")
        elif cmd[0] == "GETPRIV:" and len(cmd) == 3:
            dectime = long(cmd[1])
            salt = b64decode(cmd[2])
            # TODO: A better time check
            if dectime < time.time():
                privkey, _ = gen_temporal_keypair(masterkey, dectime, salt)
                if privkey:
                    send_privkey(privkey, sock)
                else:
                    raise RuntimeError("Invalid arguments")
            else:
                print "Client asked for key too early"
                raise RuntimeError("Decryption time has not passed.")
        # Other commands go here
        else:
            raise RuntimeError("Invalid command")
    except RuntimeError, e:
        print "ERROR: ", e.message
        send_error(e.message)
    finally:
        sock.close()


def listen(port, tlsprivkey, tlscert, masterkey):
    """
    Listen on port using TLS, accept incoming connections, and spawn a new thread to run commands.
    TODO: Can we bind the server's master secret to the TLS stuff somehow?
    :param port:
    :return:
    """
    s = socket.socket()
    sslsocket = ssl.wrap_socket(s,keyfile=tlsprivkey, certfile=tlscert, ssl_version=ssl.PROTOCOL_TLSv1_2)
    sslsocket.bind(("0.0.0.0",port))
    sslsocket.listen(10)
    while True:
        (clientsock,_) = sslsocket.accept()
        do_command(clientsock,masterkey)


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
        secret = ""
        if not os.path.exists(opts.secretfile):
            print "Secret file does not exist"
            sys.exit(-1)
        with open(opts.secretfile) as f:
            secret = base64.b64decode(f.read())

        if not secret:
            print "Error loading master secret"
            sys.exit(-1)

        listen(opts.port, opts.keyfile, opts.certfile, secret)
