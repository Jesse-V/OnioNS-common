/**
 * This file is generated by jsonrpcstub, DO NOT CHANGE IT MANUALLY!
 */

#ifndef JSONRPC_CPP_STUB_ABSTRACTSPECSERVER_H_
#define JSONRPC_CPP_STUB_ABSTRACTSPECSERVER_H_

#include <jsonrpccpp/server.h>

class AbstractSpecServer : public jsonrpc::AbstractServer<AbstractSpecServer>
{
    public:
        AbstractSpecServer(jsonrpc::AbstractServerConnector &conn, jsonrpc::serverVersion_t type = jsonrpc::JSONRPC_SERVER_V2) : jsonrpc::AbstractServer<AbstractSpecServer>(conn, type)
        {
            this->bindAndAddMethod(jsonrpc::Procedure("getData", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_INTEGER, "arg1",jsonrpc::JSON_STRING,"arg2",jsonrpc::JSON_INTEGER, NULL), &AbstractSpecServer::getDataI);
            this->bindAndAddMethod(jsonrpc::Procedure("basicGet", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_STRING,  NULL), &AbstractSpecServer::basicGetI);
            this->bindAndAddNotification(jsonrpc::Procedure("noArgNotification", jsonrpc::PARAMS_BY_NAME,  NULL), &AbstractSpecServer::noArgNotificationI);
            this->bindAndAddNotification(jsonrpc::Procedure("tellServer", jsonrpc::PARAMS_BY_NAME, "arg3",jsonrpc::JSON_ARRAY,"arg4",jsonrpc::JSON_BOOLEAN, NULL), &AbstractSpecServer::tellServerI);
        }

        inline virtual void getDataI(const Json::Value &request, Json::Value &response)
        {
            response = this->getData(request["arg1"].asString(), request["arg2"].asInt());
        }
        inline virtual void basicGetI(const Json::Value &request, Json::Value &response)
        {
            (void)request;
            response = this->basicGet();
        }
        inline virtual void noArgNotificationI(const Json::Value &request)
        {
            (void)request;
            this->noArgNotification();
        }
        inline virtual void tellServerI(const Json::Value &request)
        {
            this->tellServer(request["arg3"], request["arg4"].asBool());
        }
        virtual int getData(const std::string& arg1, int arg2) = 0;
        virtual std::string basicGet() = 0;
        virtual void noArgNotification() = 0;
        virtual void tellServer(const Json::Value& arg3, bool arg4) = 0;
};

#endif //JSONRPC_CPP_STUB_ABSTRACTSPECSERVER_H_
