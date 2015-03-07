import os
import socket
import re
import struct
import time
from cryptoutils import gen_temporal_keypair
import base64
import ssl
import ssl


def read_line(sock, maxchars=1000):
    """
    Read a full line from a socket.  If a \n does not appear in maxchars,
    return None.  If the client stops sending before we get a \n,
    return None
    :param sock:
    :param maxchars:
    :return:
    """
    chrs = 0
    line = ""
    while chrs < maxchars:
        c = sock.read(1)
        if len(c) != 1:
            return None
        if c == "\n":
            return line
        line += c
    return None


# Client network functions


def check_host_name(peercert, name):
    """Simple certificate/host name checker.  Returns True if the
    certificate matches, False otherwise.  Does not support
    wildcards."""
    # Check that the peer has supplied a certificate.
    # None/{} is not acceptable.
    if not peercert:
        return False
    if peercert.has_key("subjectAltName"):
        for typ, val in peercert["subjectAltName"]:
            if typ == "DNS" and val == name:
                return True
    else:
        # Only check the subject DN if there is no subject alternative
        # name.
        cn = None
        for attr, val in peercert["subject"]:
            # Use most-specific (last) commonName attribute.
            if attr == "commonName":
                cn = val
        if cn is not None:
            return cn == name
    return False


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
    try:
        s = socket.socket()
        s.connect((server, 31337))
        sslsock = ssl.wrap_socket(s)
        # TODO: more thorough SSL verification
        if not check_host_name(sslsock.getpeercert(), server):
            raise IOError("peer certificate does not match host name")

        sslsock.sendall(buf)

        respstr = read_line
        response = read_line(sslsock)
        if not response:
            return None
        return response.split(":")

    # TODO: Better error handling
    except:
        return None


def get_pubkey(server, dectime, salt):
    """
    Contact the server, and get its EC key
    :param server:
    :param dectime: The decryption time
    :param salt: The salt, 128-byte long
    :return: Return pubkey
    """
    msg = " ".join(["GETPRIV:", str(dectime), base64.b64encode(salt)]) + "\n"
    resp = send_query(msg, server)
    if "FAIL" in resp[0]:
        if len(resp) >= 2:
            print "ERROR getting pubkey: " + resp[1]
            return None
    elif "PUBKEY" in resp[0]:
        if len(resp) >= 2:
            return base64.b64decode(resp[1].strip())
        else:
            print "ERROR getting pubkey: unknown"
            return None
    return None


def get_privkey(server, dectime, salt):
    """
    Contact the server, and get a private key, if possible
    :param server:
    :param dectime: The decryption timestamp
    :param salt: The salt, 128-byte long
    :return: Return privkey, or None on failure
    """
    msg = " ".join(["GETPRIV:", str(dectime), base64.b64encode(salt)]) + "\n"
    resp = send_query(msg,server)
    if "FAIL" in resp[0]:
        if len(resp) >= 2:
            print "ERROR getting privkey: " + resp[1]
            return None
    elif "PRIVKEY" in resp[0]:
        if len(resp) >= 2:
            return base64.b64decode(resp[1].strip())
        else:
            print "ERROR getting privkey: unknown"
            return None
    return None


def send_reply(buf, sock):
    """
    Send a reply to the client
    :param buf: A string
    :param sock: The socket
    :return:
    """
    sock.sendall(buf)


def send_privkey(key, sock):
    """
    Send a privkey to the client.  Don't forget to base64!!!
    :param key:
    :param sock:
    :return:
    """
    buf = "PRIVKEY: " + base64.b64encode(key) + "\n"
    send_reply(buf, sock)


def send_pubkey(key, sock):
    """
    Send a pubkey to the client.  Don't forget to base64!!!
    :param key:
    :param sock:
    :return:
    """
    buf = "PUBKEY: " + base64.b64encode(key) + "\n"
    send_reply(buf, sock)


def send_error(msg, sock):
    """
    Send an error message
    :param msg:
    :param sock:
    :return:
    """
    buf = "FAIL: " + msg + "\n"
    send_reply(buf, sock)


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

    line = read_line(sock)
    cmd = line.split(" ")
    return cmd