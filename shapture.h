#ifndef SHAPTURE_H
#define SHAPTURE_H

#include <netinet/in.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>		//For standard things
#include <stdlib.h>		//malloc
#include <string.h>		//strlen
#include <netinet/ip_icmp.h>	//Provides declarations for icmp header
#include <netinet/udp.h>		//Provides declarations for udp header
#include <netinet/tcp.h>		//Provides declarations for tcp header
#include <netinet/ip.h>		//Provides declarations for ip header
#include <netinet/if_ether.h>	//For ETH_P_ALL
#include <net/ethernet.h>	//For ether_header
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <linux/if.h>   // For struct in_addr
#include <unistd.h>
#include "include/dhcp.h"
#include "include/rip.h"
#include "include/ospf.h"
#include "include/pack_dcp.h"
#include <QObject>

class Core:public QObject{
    Q_OBJECT
public:
    pthread_t start();
    void quit();

    static void *hook(void* args){
        reinterpret_cast<Core*>(args)->dcapture();
        return NULL;
    }

    Core(){
        this->running = false;
    }

    void ProcessPacket(unsigned char *, int, int);
    pack_dcp print_ip_header(unsigned char *, int, int);
    pack_dcp print_ethernet_header(unsigned char *, int, int);
    void ProcessIPPacket(unsigned char *, int, int);
    void print_arp_packet(unsigned char *, int, int);

    void print_ospf_packet(unsigned char *, int, int);
    void print_tcp_packet(unsigned char *, int, int);
    void process_udp_packet(unsigned char *, int, int);
    void print_udp_packet(unsigned char *, int, int);
    void print_icmp_packet(unsigned char *, int, int);
    void print_rip_packet(unsigned char *, int, int);
    void print_dhcp_packet(unsigned char *, int, int);
    std::string PrintData(unsigned char *, int);
    void dcapture();
signals:
    void newpack(pack_dcp pd) const;
public slots:
    void handle_switch(std::string);
private:
    std::string intf;
    int running;
};
#endif
