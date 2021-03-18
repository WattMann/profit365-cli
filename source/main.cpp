#define IPV4_REGEX "^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$"

#include <cstdio>
#include <regex>
#include <string>
#include <vector>

#include "api/profitapi.h"

void read_input(std::string* output, const char* msg) {
    char buffer[255] = {0};
    printf("%s", msg);
    scanf("%s", buffer);
    output->append(buffer);
}

bool ieq(std::string str0, std::string str1) {
    if(str0.length() != str1.length())
        return false;

    for (int index = 0; index < str0.length(); index++) {
        auto context0 = str0[index];
        auto context1 = str1[index];
        if(isalpha(context0) && isalpha(context1)) {
            if(!islower(context0))
                context0 = tolower(context0);
            if(!islower(context1))
                context1 = tolower(context1);
            if(context0 != context1)
                return false;
        } else if(context0 != context1)
            return false;
    }

    return true;
}

int main(int argc, char** argv) {
    if(argc < 2) {
        printf("Usage: profitapi <action> <parameters>\n");
        printf("Available actions:\n - gak - Generates api key\n\t parameters: none\n\n");
        return 0;
    }

    if(!strcmp(argv[1], "gak")) {
        std::string client_id, company_id, client_secret, key, username, decision;
        std::vector<std::string> denied, allowed;

        read_input(&username, "Username: ");
        read_input(&client_id, "Client ID: ");
        read_input(&company_id, "Company ID: ");
        read_input(&client_secret, "Client secret: ");
        read_input(&key, "Authorization: ");

        char buffer[255] = {0};
        std::string str;
        auto regex = std::regex(IPV4_REGEX);

        printf("\n");
        printf("Allowed IPs, type \"done\" when finished:\n");
        while(true) {
            scanf("%s", buffer);
            str = std::string(buffer);
            if(ieq(str, std::string("done")))
                break;

            if(!std::regex_match(str, regex)){
                printf("That is not a valid ipv4 adress\n");
                continue;
            }
            allowed.emplace_back(str);
            memset(&buffer, 0, 255);
        }
        printf("\n");
        printf("Denied IPs, type \"done\" when finished:\n");
        while(true) {
            scanf("%s", buffer);
            str = std::string(buffer);
            if(ieq(str, std::string("done")))
                break;

            if(!std::regex_match(str, regex)) {
                printf("That not a valid ipv4 adress\n");
                continue;
            }
            denied.emplace_back(str);
            memset(&buffer, 0, 255);
        }

        auto req = profitapi::generate_key(username, allowed, denied);
        auto header = profitapi::authorization_header(
                client_id,
                client_secret,
                key,
                profitapi::login_type::BASIC,
                company_id);

        auto comms = profitapi::communicator(header);
        auto response = comms.execute(req);

        if(response) {
            try {
                printf("\n##### Generated a new key #####\n\n ID: %s\n Key: %s\n\n###############################\n",
                       response->as_json()["id"].get<std::string>().c_str(),
                       response->as_json()["key"].get<std::string>().c_str()
                       );
            } catch (...) {
                printf("An error occurred while generating your key: %s\n", response->content.c_str());
            }
        } else {
            printf("An error occurred while generating your key\n");
        }

        return 0;
    } else {
        printf("Unknown action %s\n", argv[0]);
    }
}
