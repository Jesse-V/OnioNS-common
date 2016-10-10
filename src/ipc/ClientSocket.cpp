
#include "ClientSocket.hpp"
#include "../Log.hpp"
#include <string.h>     // strerror
#include <unistd.h>     // close
#include <arpa/inet.h>  // send, recv


ClientSocket::ClientSocket(const std::string& host, int port)
    : jsonrpc::LinuxTcpSocketClient(host, port), partialLastLine_(false)
{
  buffer_.fill(0);
}



void ClientSocket::open()
{
  Log::get().debug("Connecting to Tor's control port...");
  socketFD_ = this->Connect();
}



ClientSocket::~ClientSocket()
{
  Log::get().debug("Closing socket to control port.");
  ::close(socketFD_);
}



// adapted from jsonrpccpp/client/connectors/linuxtcpsocketclient.cpp
// const ClientSocket& ClientSocket::operator<<(const std::string& str) const
void ClientSocket::writeLine(const std::string& str)
{  // send

  Log::get().debug("Writing \"" + str + "\" to Tor's control port.");

  bool fullyWritten = false;
  std::string toSend = str + "\r\n";

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
      }

      Log::get().error(message);
    }
    else if (static_cast<size_t>(byteWritten) < toSend.size())
    {
      ssize_t len = toSend.size() - byteWritten;
      toSend = toSend.substr(byteWritten + sizeof(char), len);
    }
    else
      fullyWritten = true;
  } while (!fullyWritten);

  Log::get().debug("Write complete.");
}



std::string ClientSocket::readLine()
{  // receive

  if (lines_.empty() || (lines_.size() == 1 && partialLastLine_))
  {
    Log::get().debug("Blocking read from Tor's control port...");
    pushLines(waitForString());
  }
  else
  {
    Log::get().debug("Fast read of control port...");
    pushLines(readAvailable());  // quickly read from socket
  }

  std::string last = lines_.front();
  lines_.pop();
  Log::get().debug("Oldest Tor line: " + last);
  return last;
}



void ClientSocket::pushLines(const std::string& str)
{
  // Log::get().debug("Processing Tor response \"" + str + "\"");
  if (str.empty())
    return;

  size_t start = 0;
  size_t end = str.find(DELIMITER_CHAR);

  // append the rest of the line
  if (partialLastLine_)
  {
    lines_.back().append(str.substr(start, end - start - 1));
    start = end + 1;
    end = str.find(DELIMITER_CHAR, start);
  }

  // push back whole line
  while (end != std::string::npos)
  {
    lines_.push(str.substr(start, end - start - 1));
    start = end + 1;
    end = str.find(DELIMITER_CHAR, start);
  }

  // push any partial line
  if (start != 0 && start < str.size())
  {
    partialLastLine_ = true;
    lines_.push(str.substr(start));
  }
  else
    partialLastLine_ = false;
}



char ClientSocket::waitForChar()
{
  ssize_t nbytes = recv(socketFD_, buffer_.data(), 1, 0);
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
    }
    Log::get().error(message);
  }
  else if (nbytes == 0)
    Log::get().error("Socket closed during blocking read, did tor die?");
  else
    return buffer_[0];
}



std::string ClientSocket::readAvailable()
{
  // non-blocking
  ssize_t nb = recv(socketFD_, buffer_.data(), buffer_.size(), MSG_DONTWAIT);
  if (nb == -1)
  {
    int err = errno;
    if (err == EAGAIN || err == EWOULDBLOCK)
      return "";
    else
      Log::get().error(strerror(err));
  }
  else if (nb == 0)
    Log::get().error("Socket closed during fast read, did tor die?");
  else
    return std::string(buffer_.data(), 0, nb);
}



// will return at least one line
std::string ClientSocket::waitForString()
{
  std::string result;
  result.reserve(256);

  do
  {
    result += waitForChar();
    result += readAvailable();

  } while (result.find_last_of(DELIMITER_CHAR) == std::string::npos);

  return result;
}
