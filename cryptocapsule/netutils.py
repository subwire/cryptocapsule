import os
import socket
import re
import struct
import time
from cryptoutils import gen_temporal_keypair


# Client network functions


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


def send_query(buf, server):
    """
    Send query in buf to server
    Return the reply, or None on a socket error

    :param buf:
    :return: buf with a reply, or None on error
    """


def get_pubkey(server, dectime, salt):
    """
    Contact the server, and get its EC key
    :param server:
    :param dectime: The decryption time
    :param salt: The salt, 128-byte long
    :return: Return pubkey
    """
    # WARNING: Don't forget the base64 the binary stuff first
    # TODO: IMPLEMENT THIS
    # Should put the args together, and call send_query
    fake_masterkey = "blahblahblah"
    _, pubkey = gen_temporal_keypair(fake_masterkey, dectime, salt)
    return pubkey


def get_privkey(server, dectime, salt):
    """
    Contact the server, and get a private key, if possible
    :param server:
    :param dectime: The decryption timestamp
    :param salt: The salt, 128-byte long
    :return: Return privkey, or None on failure
    """
    # WARNING: Don't forget to base64 the binary stuff first
    # TODO: IMPLEMENT THIS
    # Should put the args together, and call send_query
    fake_masterkey = "blahblahblah"
    if dectime < time.time():
        privkey, _ = gen_temporal_keypair(fake_masterkey,dectime,salt)
        return privkey
    return None


# Server functions

def send_reply(buf, sock):
    """
    Send a reply to the client
    :param buf:
    :param sock:
    :return:
    """


def send_privkey(key, sock):
    """
    Send a privkey to the client.  Don't forget to base64!!!
    :param key:
    :param sock:
    :return:
    """


def send_pubkey(key, sock):
    """
    Send a pubkey to the client.  Don't forget to base64!!!
    :param key:
    :param sock:
    :return:
    """


def recv_query(sock):
    """
    Given an open socket, return a tuple of the format:
    (command, arg1, arg2, ...)
    where command is usually:
    - getpriv: Get a private key
    - getpub: Get a public key
    - gettime: return the current system time

    :param sock:
    :return: Tuple (command, arg1, arg2, ...) or None on failure
    """


