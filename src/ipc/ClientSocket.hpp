
#ifndef CLIENT_SOCKET_HPP
#define CLIENT_SOCKET_HPP

#include "jsonrpccpp/client/connectors/linuxtcpsocketclient.h"
#include <queue>
#include <string>

class ClientSocket : public jsonrpc::LinuxTcpSocketClient
{
 public:
  ClientSocket(const std::string&, int);
  ~ClientSocket();

  void writeLine(const std::string&);
  std::string readLine();

 private:
  void pushLines(const std::string&);
  char waitForChar();
  std::string readAvailable();
  std::string waitForString();

  static const size_t BUFFER_SIZE = 512;
  static const char DELIMITER_CHAR = 0x0A;

  int socketFD_;
  bool opened_, partialLastLine_;
  std::queue<std::string> lines_;
  std::array<char, BUFFER_SIZE> buffer_;
};

#endif
