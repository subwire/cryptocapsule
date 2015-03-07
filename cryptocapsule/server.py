import socket
import os
import re
from cryptoutils import *
from netutils import *
from base64 import b64decode, b64encode
from Crypto.Util.number import bytes_to_long, long_to_bytes
import time


def do_command(sock, masterkey):
    """
    Get a command from the socket, and do it
    :param sock:
    :return:
    """
    cmd = recv_query(sock)
    try:
        # Format: getpub, dectime, salt
        if not cmd:
            raise RuntimeError("Invalid command")
        if cmd[0] == "getpub" and len(cmd) == 3:
            dectime = long(cmd[1])
            salt = long(b64decode(cmd[2]))
            _, pubkey = gen_temporal_keypair(masterkey, dectime, salt)
            if pubkey:
                send_reply("PUBKEY: " + b64encode(pubkey), sock)
            else:
                raise RuntimeError("Invalid arguments")
        elif cmd[0] == "getpriv" and len(cmd) == 3:
            dectime = long(cmd[1])
            salt = long(b64decode(cmd[2]))
            # TODO: A better time check
            if dectime < time.time():
                privkey, _ = gen_temporal_keypair(masterkey, dectime, salt)
                if privkey:
                    send_reply("PRIVKEY: " + b64encode(privkey), sock)
                else:
                    raise RuntimeError("Invalid arguments")
            else:
                raise RuntimeError("Decryption time has not passed.")
        # Other commands go here
        else:
            raise RuntimeError("Invalid command")
    except RuntimeError, e:
        print "ERROR: ", e.message
        send_reply("FAIL: " + e.message)


def listen(port, tlsprivkey, tlspubkey, masterkey):
    """
    Listen on port using TLS, accept incoming connections, and spawn a new thread to run commands.
    TODO: Can we bind the server's master secret to the TLS stuff somehow?
    :param port:
    :return:
    """

if __name__ == '__main__':
    # TODO: Load master secret, load TLS keys, check clocks
    listen(31337, None, None, None)