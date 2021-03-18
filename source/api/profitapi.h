#ifndef PROFITAPI_PROFITAPI_H
#define PROFITAPI_PROFITAPI_H

#include <nlohmann/json.hpp>
#include <curl/curl.h>
#include <string>
#include <vector>
#include <regex>


namespace profitapi {

    enum request_type{
        POST, GET, PUT
    };

    enum login_type {
        BASIC, API_KEY
    };

    struct headers {
        std::vector<std::string> header_vector;

        void put(const std::string& header){
            header_vector.emplace_back(header);
        }
    };

    struct request {
        request_type type;
        headers header_field;
        std::string body;
        std::string context;
    };

    struct generate_key : request {
        generate_key(std::string username, std::vector<std::string> ip_allowed, std::vector<std::string> ip_denied) {
            nlohmann::json data = nlohmann::json::object();
            data["userName"] = username;
            data["ipDenied"] = ip_denied;
            data["ipAllowed"] = ip_allowed;
            header_field.put("Content-Type: application/json");
            type = request_type::POST;
            context = "/company/security/apikeys";

            body = data.dump(4);
        }
    };

    struct authorization_header {
        headers header_field;
        authorization_header(const std::string& client_id, const std::string& client_secret, const std::string& key, login_type type, const std::string& company_id) {
            header_field.put("ClientID: " + client_id);
            header_field.put("ClientSecret: " + client_secret);
            std::string authorization = "Authorization: ";
            switch (type) {
                case BASIC: {
                    authorization += "basic ";
                    break;
                }
                case API_KEY:{
                    authorization += "apiKey ";
                    break;
                }
            }
            header_field.put(authorization + key);
            header_field.put("CompanyID: " + company_id);
        }
    };

    struct payload {
        std::string content;
        nlohmann::json as_json() {
            return nlohmann::json::parse(content);
        }
    };

    size_t writer (void *ptr, size_t size, size_t nmemb, void *data) {
        ((std::string*) data)->append((char*) ptr, size * nmemb);
        return size * nmemb;
    }

    class communicator {

    private:
        std::string url = "https://api.profit365.eu/1.6";
        authorization_header auth;

    public:
        explicit communicator(authorization_header auth) : auth(std::move(auth)) {}

        payload* execute(const request &req) {
            auto handle = curl_easy_init();
            if(handle) {
                std::string _url = url + req.context;
                std::string _response;

                curl_easy_setopt(handle, CURLOPT_URL, _url.c_str());
                curl_easy_setopt(handle, CURLOPT_WRITEDATA, &_response);
                curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, writer);

                curl_slist *headers {};
                for(const auto& header : auth.header_field.header_vector)
                    headers = curl_slist_append(headers, header.c_str());
                for(const auto& header : req.header_field.header_vector)
                    headers = curl_slist_append(headers, header.c_str());

                curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers);
                curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, true);
                curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, false);

                if(req.type == request_type::POST)
                    curl_easy_setopt(handle, CURLOPT_POSTFIELDS, req.body.c_str());

                auto code = curl_easy_perform(handle);
                curl_easy_cleanup(handle);

                if(code != CURLE_OK)
                    return nullptr;
                return new payload { _response };
            }
            return nullptr;
        }

    };
}


#endif //PROFITAPI_PROFITAPI_H
