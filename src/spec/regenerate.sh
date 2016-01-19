#/bin/bash

#LD_PRELOAD="/usr/local/lib/libjsonrpccpp-common.so /usr/local/lib/libjsonrpccpp-stub.so.0" jsonrpcstub rpc_spec.json --cpp-server=AbstractStubServer --cpp-client=StubClient

jsonrpcstub rpc_spec.json --cpp-server=AbstractSpecServer --cpp-client=AbstractSpecClient
mv abstractspecserver.h AbstractSpecServer.h
mv abstractspecclient.h AbstractSpecClient.h
