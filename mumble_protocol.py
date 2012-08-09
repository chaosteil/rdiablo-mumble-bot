#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import optparse
import platform
import struct

import Mumble_pb2
from twisted.internet import reactor, protocol, ssl
from twisted.internet.protocol import ClientFactory


log = logging.getLogger(__name__)


class MumbleProtocol(protocol.Protocol):
    VERSION_MAJOR = 1
    VERSION_MINOR = 2
    VERSION_PATCH = 3

    VERSION_DATA = (VERSION_MAJOR << 16) \
                    | (VERSION_MINOR << 8) \
                    | (VERSION_PATCH)

    # From the Mumble protocol documentation
    PREFIX_FORMAT = ">HI"
    PREFIX_LENGTH = 6

    # This specific order of IDs is extracted from
    # https://github.com/mumble-voip/mumble/blob/master/src/Message.h
    ID_MESSAGE = [
        Mumble_pb2.Version,
        Mumble_pb2.UDPTunnel,
        Mumble_pb2.Authenticate,
        Mumble_pb2.Ping,
        Mumble_pb2.Reject,
        Mumble_pb2.ServerSync,
        Mumble_pb2.ChannelRemove,
        Mumble_pb2.ChannelState,
        Mumble_pb2.UserRemove,
        Mumble_pb2.UserState,
        Mumble_pb2.BanList,
        Mumble_pb2.TextMessage,
        Mumble_pb2.PermissionDenied,
        Mumble_pb2.ACL,
        Mumble_pb2.QueryUsers,
        Mumble_pb2.CryptSetup,
        Mumble_pb2.ContextActionModify,
        Mumble_pb2.ContextAction,
        Mumble_pb2.UserList,
        Mumble_pb2.VoiceTarget,
        Mumble_pb2.PermissionQuery,
        Mumble_pb2.CodecVersion,
        Mumble_pb2.UserStats,
        Mumble_pb2.RequestBlob,
        Mumble_pb2.ServerConfig
    ]

    # Reversing the IDs, so we are able to backreference.
    MESSAGE_ID = dict([(v, k) for k, v in enumerate(ID_MESSAGE)])

    PING_REPEAT_TIME = 5

    def __init__(self, username="MumbleTwistedBot", password=None, tokens=[]):
        self.received = ""

        self.username = username
        self.password = password
        self.tokens = []

    def recvProtobuf(self, msg_type, message):
        log.debug("Received message '%s' (%d):\n%s" \
                  % (message.__class__, msg_type, str(message)))

    def connectionMade(self):
        log.debug("Connected to server.")

        # In the mumble protocol you must first send your current message
        # and immediately after that the authentication data.
        #
        # The mumble server will respond with a version message right after
        # this one.
        version = Mumble_pb2.Version()

        version.version = MumbleProtocol.VERSION_DATA
        version.release = "%d.%d.%d" % (MumbleProtocol.VERSION_MAJOR,
                                       MumbleProtocol.VERSION_MINOR,
                                       MumbleProtocol.VERSION_PATCH)
        version.os = platform.system()
        version.os_version = "Mumble 1.2.3 Twisted Protocol"

        # Here we authenticate
        auth = Mumble_pb2.Authenticate()
        auth.username = self.username
        if self.password:
            auth.password = self.password
        for token in self.tokens:
            auth.tokens.append(token)

        # And now we send both packets one after another
        self.sendProtobuf(version)
        self.sendProtobuf(auth)

        # Then we initialize our ping handler
        self.init_ping()

    def init_ping(self):
        # Call ping every PING_REPEAT_TIME seconds.
        reactor.callLater(MumbleProtocol.PING_REPEAT_TIME, self.ping_handler)

    def ping_handler(self):
        log.debug("Sending ping")

        # Ping has only optional data, no required
        ping = Mumble_pb2.Ping()
        self.sendProtobuf(ping)

        self.init_ping()

    def dataReceived(self, recv):
        # Append our received data
        self.received = self.received + recv

        # If we have enough bytes to read the header, we do that
        while len(self.received) >= MumbleProtocol.PREFIX_LENGTH:
            msg_type, length = \
                    struct.unpack(MumbleProtocol.PREFIX_FORMAT,
                                  self.received[:MumbleProtocol.PREFIX_LENGTH])

            full_length = MumbleProtocol.PREFIX_LENGTH + length

            log.debug("Length: %d" % length)
            log.debug("Message type: %d" % msg_type)

            # Check if this this a valid message ID
            if msg_type not in MumbleProtocol.MESSAGE_ID.values():
                log.error('Message ID not available.')
                self.transport.loseConnection()
                return

            # We need to check if we have enough bytes to fully read the
            # message
            if len(self.received) < full_length:
                log.debug("Need to fill data")
                return

            # Read the specific message
            msg = MumbleProtocol.ID_MESSAGE[msg_type]()
            msg.ParseFromString(
                self.received[MumbleProtocol.PREFIX_LENGTH:
                              MumbleProtocol.PREFIX_LENGTH + length])

            # Handle the message
            try:
                self.recvProtobuf(msg_type, msg)
            except Exception:
                log.error("Exception while handling data.")
                # We abort on exception, because that's the proper thing to do
                self.transport.loseConnection()
                raise

            self.received = self.received[full_length:]

    def sendProtobuf(self, message):
        # We find the message ID
        msg_type = MumbleProtocol.MESSAGE_ID[message.__class__]
        # Serialize the message
        msg_data = message.SerializeToString()
        length = len(msg_data)

        # Compile the data with the header
        data = struct.pack(MumbleProtocol.PREFIX_FORMAT, msg_type, length) \
                + msg_data

        # Send the data
        self.transport.write(data)


class MumbleProtocolFactory(ClientFactory):
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def buildProtocol(self, addr):
        return MumbleProtocol(username=self.username,
                              password=self.password)


def mumble_connect(host, port, factory):
    """ Helper function for connecting to a mumble server via SSH. """
    log.info("Connecting to %s:%d via SSL" % (host, port))
    reactor.connectSSL(host, port,
                       factory, ssl.ClientContextFactory())


def main():
    # This helps us run a standalone connection test
    optp = optparse.OptionParser(description="Mumble 1.2.3 protocol",
                                 prog="mumble_protocol.py",
                                 version="%prog 1.0",
                                 usage="%prog -u \"Mumble Bot\" -w \"password\"")
    optp.add_option("-u", "--user", help="Username for the mumble bot",
                    action="store", type="string", default="Mumble Bot")
    optp.add_option("-w", "--password", help="Password for the server",
                    action="store", type="string", default=None)
    optp.add_option("-s", "--server", help="Server to connect to",
                    action="store", type="string", default="localhost")
    optp.add_option("-p", "--port", help="Port to connect to",
                    action="store", type="int", default=64738)
    optp.add_option("-d", "--debug", help="Enable debug output",
                    action="store_true")

    opt, args = optp.parse_args()

    if opt.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    log.info("Mumble username: '%s'" % opt.user)
    factory = MumbleProtocolFactory(username=opt.user, password=opt.password)

    mumble_connect(opt.server, opt.port, factory)
    reactor.run()


if __name__ == '__main__':
    main()
