
#include "ClientSocket.hpp"
#include <string.h>     // strerror
#include <unistd.h>     // close
#include <arpa/inet.h>  // send, recv


ClientSocket::ClientSocket(const std::string& host, int port)
    : jsonrpc::LinuxTcpSocketClient(host, port),
      opened_(false),
      partialLastLine_(false)
{
  socketFD_ = this->Connect();
  buffer_.fill(0);
}



ClientSocket::~ClientSocket()
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

      throw std::runtime_error(message);
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



//#include <iostream>
std::string ClientSocket::readLine()
{  // receive

  if (lines_.empty() || lines_.size() == 1 && partialLastLine_)
  {
    // std::cout << "not complete" << std::endl;
    pushLines(waitForString());
  }
  else
  {
    // std::cout << "!empty" << std::endl;
    pushLines(readAvailable());  // quickly read from socket
    // if (partialLastLine_)
    //  pushLines(waitForString());
  }


  std::string last = lines_.front();
  // std::cout << "LAST &" << last << "&\n";
  lines_.pop();
  return last;

  /*
    pop off oldest line, readSocket(), and return line
    if buffer empty, read 1 char blocking, then read more


  char buffer[BUFFER_SIZE];

  int nbytes = recv(socketFD_, buffer, BUFFER_SIZE, MSG_DONTWAIT);
  if (nbytes == -1)
  {
    int err = errno;
    if (err == EAGAIN)
      std::cout << "EAGAIN" << std::endl;
    else if (err == EWOULDBLOCK)
      std::cout << "EWOULDBLOCK" << std::endl;
    else
      std::cout << strerror(err) << std::endl;
  }
  else
    std::cout << nbytes << std::endl;



  /*
    while (true)
    {
      int nbytes = recv(socketFD_, buffer, BUFFER_SIZE, 0);
      if (nbytes == -1)
      {
        std::string message = "recv() failed";
        switch (errno)
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

        throw std::runtime_error(message);
      }
      else
      {
        std::string tmp(buffer, nbytes);
        std::size_t eol = tmp.find(DELIMITER_CHAR);

        if (eol == std::string::npos)
          result.append(tmp);
        else
        {
          result.append(tmp, 0, eol - 1);
          break;
        }
      }
    }
  */

  // return *this;
}



void ClientSocket::pushLines(const std::string& str)
{
  if (str.empty())
    return;

  size_t start = 0;
  size_t end = str.find(DELIMITER_CHAR);

  // append the rest of the line
  if (partialLastLine_)
  {
    // std::cout << "Appending remainder: &" << str.substr(start, end - start -
    // 1)
    //          << "&\n";
    lines_.back().append(str.substr(start, end - start - 1));
    start = end + 1;
    end = str.find(DELIMITER_CHAR, start);
  }

  // push back whole line
  while (end != std::string::npos)
  {
    // std::cout << "Pushing whole: &" << str.substr(start, end - start - 1)
    //          << "&\n";
    lines_.push(str.substr(start, end - start - 1));
    start = end + 1;
    end = str.find(DELIMITER_CHAR, start);
  }

  // push any partial line
  if (start != 0 && start < str.size())
  {
    // std::cout << "Pushing partial due to " << start << " " << str.size()
    //          << "&\n";
    // std::cout << "Pushing partial: &" << str.substr(start) << "&\n";
    partialLastLine_ = true;
    lines_.push(str.substr(start));
  }
  else
    partialLastLine_ = false;
}



char ClientSocket::waitForChar()
{
  int nbytes = recv(socketFD_, buffer_.data(), 1, 0);
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
    throw std::runtime_error(message);
  }
  else if (nbytes == 0)
    throw std::runtime_error("Socket connection closed 1.");
  else
    return buffer_[0];
}



std::string ClientSocket::readAvailable()
{
  // non-blocking
  int nbytes = recv(socketFD_, buffer_.data(), buffer_.size(), MSG_DONTWAIT);
  if (nbytes == -1)
  {
    int err = errno;
    if (err == EAGAIN || err == EWOULDBLOCK)
      return "";
    else
      throw std::runtime_error(strerror(err));
  }
  else if (nbytes == 0)
    throw std::runtime_error("Socket connection closed 2.");
  else
    return std::string(buffer_.data(), 0, nbytes);
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
