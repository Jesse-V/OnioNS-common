/**
 * This file is generated by jsonrpcstub, DO NOT CHANGE IT MANUALLY!
 */

#ifndef JSONRPC_CPP_STUB_SPECCLIENT_H_
#define JSONRPC_CPP_STUB_SPECCLIENT_H_

#include <jsonrpccpp/client.h>

class SpecClient : public jsonrpc::Client
{
 public:
  SpecClient(jsonrpc::IClientConnector& conn,
             jsonrpc::clientVersion_t type = jsonrpc::JSONRPC_CLIENT_V2)
      : jsonrpc::Client(conn, type)
  {
  }

  int getData(const std::string& arg1,
              int arg2) throw(jsonrpc::JsonRpcException)
  {
    Json::Value p;
    p["arg1"] = arg1;
    p["arg2"] = arg2;
    Json::Value result = this->CallMethod("getData", p);
    if (result.isInt())
      return result.asInt();
    else
      throw jsonrpc::JsonRpcException(
          jsonrpc::Errors::ERROR_CLIENT_INVALID_RESPONSE,
          result.toStyledString());
  }
  std::string basicGet() throw(jsonrpc::JsonRpcException)
  {
    Json::Value p;
    p = Json::nullValue;
    Json::Value result = this->CallMethod("basicGet", p);
    if (result.isString())
      return result.asString();
    else
      throw jsonrpc::JsonRpcException(
          jsonrpc::Errors::ERROR_CLIENT_INVALID_RESPONSE,
          result.toStyledString());
  }
  void noArgNotification() throw(jsonrpc::JsonRpcException)
  {
    Json::Value p;
    p = Json::nullValue;
    this->CallNotification("noArgNotification", p);
  }
  void tellServer(const Json::Value& arg3,
                  bool arg4) throw(jsonrpc::JsonRpcException)
  {
    Json::Value p;
    p["arg3"] = arg3;
    p["arg4"] = arg4;
    this->CallNotification("tellServer", p);
  }
};

#endif  // JSONRPC_CPP_STUB_SPECCLIENT_H_
