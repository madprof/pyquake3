#!/usr/bin/env python

"""
Python Quake 3 Library
$Id: pyquake3.py 456 2009-11-11 00:22:58Z prof $

A module to talk to Quake 3 servers from Python scripts.
Note that the current version was tested only with Urban
Terror servers, so there may be subtle problems when you
use it for actual Quake 3 or Open Arena servers. Also we
are not 100% backwards compatible to earlier releases of
pyquake3. Bummer! :-/ Most "missing" features are now in
the Connection class if you care to look.

http://misc.slowchop.com/misc/wiki/pyquake3
Copyright (C) 2006-2007 Gerald Kaszuba
http://www.urbanban.com/pyquake3/
Copyright (C) 2009 |ALPHA| Mad Professor <alpha.mad.professor@gmail.com>

Released under the GPL 2, see file COPYING for details.
"""

import re as RE
import socket as SO

class Error(Exception):
    """Base class for exceptions in this module."""
    pass

class ConnectionError(Error):
    """Error in network connection or protocol."""
    pass

class Connection(object):
    """
    Low level connection to a Quake 3 server. Note that we
    bridge two levels of abstraction here, networking and
    Quake 3 packet format. But who cares? :-D

    The trickiest part here is managing responses from the
    server as some commands generate multiple UDP packets!
    Check out receive_all() below for details.
    """

    PREFIX_LENGTH = 4
    PACKET_PREFIX = "\xff" * PREFIX_LENGTH

    def __init__(self, host, port, size=8192, timeout=1.0, retries=5):
        """
        Create a pseudo-connection to "host" and "port"; we
        try to give UDP communication a semblance of sanity.

        The internal UDP packet buffer will be "size" bytes,
        we'll wait "timeout" seconds for each response, and
        we'll retry commands "retries" times before failing.
        """
        # we neither want to deal with blocking nor with
        # timeouts that are plain silly in 2009...
        assert 0.1 <= timeout <= 4.0
        assert 4096 <= size <= 65536
        assert 1 <= retries <= 10
        self.socket = SO.socket(SO.AF_INET, SO.SOCK_DGRAM)
        # for SOCK_DGRAM connect() slips a default address
        # into each datagram; furthermore only data from the
        # "connected" address is delivered back; pretty neat
        self.socket.connect((host, port))
        self.socket.settimeout(timeout)
        self.host = host
        self.port = port
        self.size = size
        self.timeout = timeout
        self.retries = retries

    def send(self, data):
        """
        Send given data as a properly formatted packet.
        """
        self.socket.send("%s%s\n" % (Connection.PACKET_PREFIX, data))

    def receive(self):
        """
        Receive a properly formatted packet and return the
        unpacked (type, data) response pair. Note that one
        packet will be read, not multiple; use receive_all
        to get all packets up to a timeout.
        """
        packet = self.socket.recv(self.size)

        if packet.find(Connection.PACKET_PREFIX) != 0:
            raise ConnectionError("Malformed packet")

        first_line_length = packet.find("\n")
        if first_line_length == -1:
            raise ConnectionError("Malformed packet")

        response_type = packet[Connection.PREFIX_LENGTH:first_line_length]
        response_data = packet[first_line_length+1:]

        return (response_type, response_data)

    def receive_all(self):
        """
        Receive a sequence of packets until a timeout
        exception. Check that all packets share a type,
        if so merge the data from all packets. Return
        the merged (type, data) response pair.
        """
        packets = []

        try:
            while True:
                packet = self.receive()
                packets.append(packet)
        except SO.timeout:
            # we timed out, so we'll assume that the
            # sequence of packets has ended; not sure
            # if this is a good idea...
            pass

        assert len(packets) > 0
        status, data = packets[0]
        for packet in packets[1:]:
            assert status == packet[0]
            data += packet[1]

        return (status, data)

    def command(self, cmd):
        """
        Execute given command and return (type, data)
        response pair. Commands will be retried for a
        number of times. (All response packets will be
        read and merged using receive_all.)
        """
        retries = self.retries
        response = None
        while retries > 0:
            self.send(cmd)
            try:
                response = self.receive_all()
            except Exception:
                # TODO: really catch Exception here? no
                # SO.error or something?
                retries -= 1
            else:
                return response
        raise ConnectionError("No response after %d attempts." % self.retries)

    def close(self):
        """Close connection."""
        self.socket.close()

class REs(object):
    """
    A container for regular expressions used to parse the
    result of certain well-known server commands. In best
    Perl tradition, they are totally unreadable. 8-O
    """
    # parse a player line from "getstatus" command
    # 11 50 "|ALPHA|MarvinTheSpud"
    GETSTATUS = RE.compile(r'^(-?)(\d+) (\d+) "(.*)"')
    # parse a player line from "rcon status" command
    # 2 0 70 |ALPHA| Mad Professor^7 0 127.0.0.1:35107 229 25000
    RCON_STATUS = RE.compile(r'\s*(\d+)\s+(-?)(\d+)\s+(\d+)\s+(.*)\^7\s+(\d+)\s+(\S*)\s+(\d+)\s+(\d+)')

class Player(object):
    """Record collecting information about a player."""

    def __init__(self):
        """Create empty record with lots of None fields."""
        # information from getstatus request
        self.frags = None
        self.ping = None
        self.name = None
        # information from rcon status request
        self.address = None
        self.slot = None
        self.lastmsg = None
        self.qport = None
        self.rate = None
        # information from dumpuser request
        self.guid = None
        self.variables = None

    def __str__(self):
        """Short summary of name, address, and guid."""
        return ("Player<name: %s; address: %s; guid: %s>" %
            (self.name, self.address, self.guid))

class Server(object):
    """Record collecting information about a server."""

    def __init__(self, filter_colors=True):
        """Create empty record with lots of None fields."""
        # meta information before connect
        self.filter = filter_colors
        self.host = None
        self.port = None
        # shortcuts to well-known variables
        self.name = None
        self.game = None
        self.map = None
        self.protocol = None
        self.version = None
        # dict of *all* server variables
        self.variables = {}
        # list of players
        self.players = []

    def address(self):
        """Helper to get "ip:port" for a server."""
        return "%s:%s" % (self.host, self.port)

    def get_address(self):
        """Compatibiltiy alias for address()."""
        return self.address()

    def command(self, command):
        """Wrapper calling Connection.command() for a server."""
        return self.connection.command(command)

    def filter_name(self, name):
        """Helper to remove Quake 3 color codes from player names."""
        result = ""
        i = 0
        while i < len(name):
            if name[i] == "^":
                i += 2
            else:
                result += name[i]
                i += 1
        return result

    def __str__(self):
        """Short summary of name, address, and map."""
        return ("Server<name: %s; address: %s; map: %s>" %
            (self.name, self.address(), self.map))

class Parser(object):
    """
    Mixin class to parse various server responses into
    useful information. Should be applied to subclasses
    of Server.
    """
    def parse_getstatus_variables(self, data):
        """
        Parse variables portion of getstatus response.
        The format is "\\key\\value\\key\\value..." and
        we turn that into a dictionary; selected values
        are also made fields.
        """
        data = data.split("\\")[1:]
        assert len(data) % 2 == 0
        keys = data[0::2]
        values = data[1::2]
        self.variables = dict(zip(keys, values))

        self.name = self.variables["sv_hostname"]
        self.game = self.variables["gamename"]
        self.map = self.variables["mapname"]
        self.protocol = self.variables["protocol"]
        self.version = self.variables["version"]

    def parse_getstatus_players(self, data):
        """
        Parse players portion of getstatus response.
        TODO
        """
        assert len(data) > 0
        self.players = []

        for record in data:

            match = REs.GETSTATUS.match(record)
            if match:
                negative, frags, ping, name = match.groups()
                if negative == "-":
                    frags = "-" + frags
                if self.filter:
                    name = self.filter_name(name)

                player = Player()
                player.frags = int(frags)
                player.ping = int(ping)
                player.name = name
                self.players.append(player)

    def parse_getstatus(self, data):
        """
        Parse server response to getstatus command. The
        first line of the response has lots of variables
        while the following lines have players.
        """
        data = data.strip().split("\n")

        variables = data[0].strip()
        players = data[1:]

        self.parse_getstatus_variables(variables)

        if len(players) > 0:
            self.parse_getstatus_players(players)

    def getstatus(self):
        """
        Basic server query for public information only.
        """
        status, data = self.connection.command("getstatus")
        if status == "statusResponse":
            self.parse_getstatus(data)

    def update(self):
        """
        Compatibiltiy alias for getstatus().
        """
        self.getstatus()

    def parse_rcon_status_players(self, data):
        """
        Parse players portion of RCON status response.
        TODO
        """
        assert len(data) > 0
        self.players = []

        for record in data:

            match = REs.RCON_STATUS.match(record)
            if match:
                slot, negative, frags, ping, name, lastmsg, address, qport, rate = match.groups()
                if negative == "-":
                    frags = "-" + frags
                if self.filter:
                    name = self.filter_name(name)

                player = Player()
                player.slot = int(slot)
                player.frags = int(frags)
                player.ping = int(ping)
                player.name = name
                player.lastmsg = int(lastmsg)
                player.address = address
                player.qport = int(qport)
                player.rate = int(rate)
                self.players.append(player)

    def parse_rcon_status(self, data):
        """
        Parse RCON status response. There are at least
        three lines, the first is "map: bla" so we can
        get an updated map variable. The next two are
        the table header, all remaining ones (if any)
        are players, one player on each line.
        """
        data = data.strip().split("\n")
        mapname = data[0].strip().split(": ")[1].strip()

        self.variables["mapname"] = mapname
        self.map = mapname

        players = data[3:]
        if len(players) > 0:
            self.parse_rcon_status_players(players)

    def rcon_status(self):
        """
        TODO
        """
        status, data = self.rcon_command("status")
        if status == "print" and data.startswith("map"):
            self.parse_rcon_status(data)

    def rcon_update(self):
        """
        Compatibiltiy alias for rcon_status().
        """
        self.rcon_status()

    def parse_dumpuser(self, player, data):
        """
        Two header lines followed by "key value" lines
        separated by (lots of) spaces; spaces in values
        are present too, so we split at most once.
        TODO
        """
        data = data.strip().split("\n")[2:]
        variables = {}
        for record in data:
            # we split at most once to not lose spaces
            # inside a value (a name for example)
            separated = record.strip().split(None, 1)
            key = separated[0].strip()
            value = separated[1].strip()
            variables[key] = value

        # we need to avoid updating one player with
        # information for another, so we check for
        # some equalities before we believe the new
        # data to apply
        if player.address == variables["ip"] and player.rate == int(variables["rate"]):
            # alright, update the player object with new information
            player.variables = variables
            player.guid = variables["cl_guid"]

    def rcon_dumpuser_all(self):
        """
        TODO
        """
        for player in self.players:
            status, data = self.rcon_command("dumpuser %d" % player.slot)
            assert status == "print" and data.startswith("userinfo")
            self.parse_dumpuser(player, data)

class Guest(Server, Parser):
    """
    Server implementation that cannot perform any RCON
    commands. The right class if you are browsing some
    random servers.
    """
    def __init__(self, host, port, filter_colors=True):
        """
        TODO
        """
        Server.__init__(self, filter_colors)
        self.connection = Connection(host, port)
        self.host = host
        self.port = port

class Administrator(Server, Parser):
    """
    Server implementation that can perform any command
    an administrator can. The right class if you're in
    the business of writing admin interfaces.
    """
    def __init__(self, host, port, rcon_password, filter_colors=True):
        """
        TODO
        """
        Server.__init__(self, filter_colors)
        self.connection = Connection(host, port)
        self.host = host
        self.port = port
        self.rcon_password = rcon_password

    def rcon_command(self, command):
        """
        Execute an RCON command through the underlying
        connection and return the (type, data) response
        pair.
        """
        command = "rcon \"%s\" %s" % (self.rcon_password, command)
        status, data = self.connection.command(command)
        # TODO: why make this into an exception? the regular
        # command() method doesn't raise?
        if status.startswith(("Bad rcon", "No rcon")):
            raise ConnectionError(status.strip())
        return (status, data)

def PyQuake3(server, rcon_password=None, filter_colors=True):
    """
    Factory method for some backwards compatibility.
    """
    host, port = server.split(":")
    port = int(port)
    if rcon_password is None:
        return Guest(host, port, filter_colors)
    else:
        return Administrator(host, port, rcon_password, filter_colors)

def test_connection():
    c = Connection("tx.urbanban.com", 27960)

    status = c.command("getstatus")
    assert len(status) > 0
    print status

    status = c.command("rcon status")
    assert status[1].startswith("Bad rcon")
    print status

    c.close()

    try:
        print c.command("getstatus")
    except SO.error as e:
        assert e is not None
        print e

    try:
        d = Connection("tx.urbanban.com", 27969)
        d.command("getstatus")
    except ConnectionError as e:
        assert e is not None
        print e

def test_updates_and_players():
    # put your own server/password here to test
    a = Administrator("tx.urbanban.com", 27960, "you'll never guess :-D")
    a.update()
    for p in a.players:
        print p
    a.rcon_update()
    for p in a.players:
        print p
    a.rcon_dumpuser_all()
    for p in a.players:
        print p

if __name__ == '__main__':
    test_connection()
    test_updates_and_players()
