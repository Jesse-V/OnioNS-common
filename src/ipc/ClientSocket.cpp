
#include "ClientSocket.hpp"
#include <string>
#include <string.h>     // strerror
#include <unistd.h>     // close
#include <arpa/inet.h>  // send, recv

#define BUFFER_SIZE 64
#define DELIMITER_CHAR char(0x0A)


ClientSocket::ClientSocket(const std::string& host, int port)
    : jsonrpc::LinuxTcpSocketClient(host, port), opened_(false)
{
}



ClientSocket::~ClientSocket()
{
  if (opened_)
    close();
}



void ClientSocket::open()
{
  socketFD_ = this->Connect();
  opened_ = true;
}



void ClientSocket::close()
{
  ::close(socketFD_);
}



// adapted from jsonrpccpp/client/connectors/linuxtcpsocketclient.cpp
const ClientSocket& ClientSocket::operator<<(const std::string& str) const
{  // send

  bool fullyWritten = false;
  std::string toSend = str;

  do
  {
    ssize_t byteWritten = send(socketFD_, toSend.c_str(), toSend.size(), 0);

    if (byteWritten == -1)
    {
      std::string message = "send() failed";

      int err = errno;
      switch (err)
      {
        case EACCES:
        case EWOULDBLOCK:
        case EBADF:
        case ECONNRESET:
        case EDESTADDRREQ:
        case EFAULT:
        case EINTR:
        case EINVAL:
        case EISCONN:
        case EMSGSIZE:
        case ENOBUFS:
        case ENOMEM:
        case ENOTCONN:
        case ENOTSOCK:
        case EOPNOTSUPP:
        case EPIPE:
          message = strerror(err);
          break;
      }

      throw jsonrpc::JsonRpcException(jsonrpc::Errors::ERROR_CLIENT_CONNECTOR,
                                      message);
    }
    else if (static_cast<size_t>(byteWritten) < toSend.size())
    {
      int len = toSend.size() - byteWritten;
      toSend = toSend.substr(byteWritten + sizeof(char), len);
    }
    else
      fullyWritten = true;
  } while (!fullyWritten);

  return *this;
}



const ClientSocket& ClientSocket::operator>>(std::string& result) const
{  // receive

  char buffer[BUFFER_SIZE];

  do
  {
    int nbytes = recv(socketFD_, buffer, BUFFER_SIZE, 0);
    if (nbytes == -1)
    {
      std::string message = "recv() failed";
      int err = errno;
      switch (err)
      {
        case EWOULDBLOCK:
        case EBADF:
        case ECONNRESET:
        case EFAULT:
        case EINTR:
        case EINVAL:
        case ENOMEM:
        case ENOTCONN:
        case ENOTSOCK:
          message = strerror(err);
          break;
      }

      throw jsonrpc::JsonRpcException(jsonrpc::Errors::ERROR_CLIENT_CONNECTOR,
                                      message);
    }
    else
    {
      std::string tmp;
      tmp.append(buffer, nbytes);
      result.append(buffer, nbytes);
    }
  } while (result.find(DELIMITER_CHAR) == std::string::npos);

  return *this;
}
