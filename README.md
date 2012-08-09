rdiablo-mumble-bot
==================

Used for kicking people running on open proxies. Open proxy detection via
blacklist DNS.

Before running, make sure that google protobuf is installed as well as twisted.

You can get the Mumble.proto file from
https://github.com/mumble-voip/mumble/blob/master/src/Mumble.proto

Compile the proto file with the following parameters:
    protoc --python_out=. Mumble.proto

This will generate a `Mumble_pb2.py` file in this directory.
