
#ifndef CLIENT_SOCKET_HPP
#define CLIENT_SOCKET_HPP

#include "jsonrpccpp/client/connectors/linuxtcpsocketclient.h"

class ClientSocket : public jsonrpc::LinuxTcpSocketClient
{
 public:
  ClientSocket(const std::string&, int);
  ~ClientSocket();
  const ClientSocket& operator<<(const std::string&) const;
  const ClientSocket& operator>>(std::string&) const;

  void open();
  void close();

 private:
  int socketFD_;
  bool opened_;
};

#endif
