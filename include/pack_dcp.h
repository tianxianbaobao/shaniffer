#ifndef PACK_H
#define PACK_H
#include <cstring>
#include <string>
#include <QMetaType>

class pack_dcp{
    public:
        int no;
        std::string srcip;
        std::string desip;
        int proto;
        std::string content;

        pack_dcp(){}
        pack_dcp(int no, std::string srcip, std::string desip, int proto, std::string content){
            this->no = no;
            this->srcip = srcip;
            this->desip = desip;
            this->proto = proto;
            this->content = content;
        }

        std::string getProto(){
            switch(this->proto){
                case 0: return std::string("eth");
                case 1: return std::string("icmp");
                case 2: return std::string("igmp");
                case 6: return std::string("tcp");
                case 17: return std::string("udp");
                case 89: return std::string("ospf");
                case 100: return std::string("dhcp");
                case 101: return std::string("rip");
                case 0x0608: return std::string("arp");
                case 0x0008: return std::string("ip");
                default: return std::string("unknown");
            }
        }
};
Q_DECLARE_METATYPE(pack_dcp);
#endif
