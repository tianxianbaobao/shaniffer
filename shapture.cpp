#include "shapture.h"
#include <string>
#include <cstring>
#include <pthread.h>

struct sockaddr_in source, dest;
int tcp = 0, udp = 0, icmp = 0, arp = 0, ospf = 0, others = 0, igmp = 0, total = 0, dhcp =0, rip = 0, i, j;

pthread_t Core::start(){
    this->running = true;
    pthread_t tid;
    pthread_create(&tid, NULL, hook, this);
    return tid;
}

void Core::quit(){
    this->running = false;
}

void Core::dcapture()
{
	int saddr_size, data_size;
	struct sockaddr saddr;
	char *interface = new char[this->intf.size() + 1];
    strcpy(interface,intf.c_str());
    int index = 0;

	unsigned char *buffer = (unsigned char *)malloc(65536);	//Its Big!

	printf("Starting ...\n");

	int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if (interface != NULL) {
		printf("listening on %s ...\n", interface);
		setsockopt(sock_raw, SOL_SOCKET, SO_BINDTODEVICE, interface,
			   strlen(interface) + 1);
	}
	if (sock_raw < 0) {
		//Print the error with proper message
		perror("Socket Error");
		return;
	}
	while (this->running) {
		saddr_size = sizeof saddr;
		//Receive a packet
		data_size =
		    recvfrom(sock_raw, buffer, 65536, 0, &saddr,
			     (socklen_t *) & saddr_size);
		if (data_size < 0) {
			printf("Recvfrom error , failed to get packets\n");
			return;
		}
		//Now process the packet
        index ++;
		ProcessPacket(buffer , data_size, index);
	}
	close(sock_raw);
	printf("Finished");
	return;
}

void Core::ProcessIPPacket(unsigned char *buffer, int size, int index)
{
	struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));

	switch (iph->protocol)	//Check the Protocol and do accordingly...
	{
	case 1:		//ICMP Protocol
		++icmp;
		print_icmp_packet(buffer, size, index);
		break;

	case 2:		//IGMP Protocol
		++igmp;
		break;

	case 6:		//TCP Protocol
		++tcp;
		print_tcp_packet(buffer, size, index);
		break;

	case 17:		//UDP Protocol
		++udp;
		process_udp_packet(buffer, size, index);
		break;

    case 89:
        ++ospf;
        print_ospf_packet(buffer, size, index);
        break;

	default:		//Some Other Protocol
		++others;
		break;
	}
}

void Core::ProcessPacket(unsigned char *buffer, int size, int index)
{
	int ether_proto = ((struct ethhdr *)buffer)->h_proto;
	++total;
	switch (ether_proto) {
	case 0x0608:
		++arp;
		print_arp_packet(buffer, size, index);
		break;
	case 0x0008:
		ProcessIPPacket(buffer, size, index);
		break;
	default:		//Some Other Protocol.
		++others;
		break;
	}
	printf
	    ("TCP : %d   UDP : %d (DHCP : %d   RIP : %d)   ICMP : %d   IGMP : %d   ARP : %d    OSPF : %d   Others : %d   Total : %d\r",
	     tcp, udp, dhcp, rip, icmp, igmp, arp, ospf, others, total);
}

pack_dcp Core::print_ethernet_header(unsigned char *Buffer, int Size, int index)
{
	struct ethhdr *eth = (struct ethhdr *)Buffer;
    pack_dcp ret;
    ret.no = index;
    ret.proto = 0;
    char tmp[256];
    ret.content = "";

	sprintf(tmp, "\n"); ret.content += std::string(tmp);
	sprintf(tmp, "Ethernet Header\n");ret.content += std::string(tmp);
	sprintf(tmp,
		"   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",
		eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
		eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);ret.content += std::string(tmp);
	sprintf(tmp,
		"   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",
		eth->h_source[0], eth->h_source[1], eth->h_source[2],
		eth->h_source[3], eth->h_source[4], eth->h_source[5]);ret.content += std::string(tmp);
	sprintf(tmp, "   |-Protocol            : %u \n",
		(unsigned short)eth->h_proto);ret.content += std::string(tmp);
    return ret;
}

void Core::print_arp_packet(unsigned char *Buffer, int Size, int index)
{
	struct ether_arp *arp = (struct ether_arp *)(Buffer + sizeof(struct ethhdr));
	struct arphdr *arph = (struct arphdr *)arp;
    
	pack_dcp msg = print_ethernet_header(Buffer, Size, index);

    char tmp[256];
	sprintf(tmp, "\n");msg.content += std::string(tmp);
	sprintf(tmp, "ARP Header\n");msg.content += std::string(tmp);
	sprintf(tmp, "   |-ar_hrd      : %u\n", ntohs(arph->ar_hrd));msg.content += std::string(tmp);
	sprintf(tmp, "   |-ar_pro      : %u\n", ntohs(arph->ar_pro));msg.content += std::string(tmp);
	sprintf(tmp, "   |-Length of Hardware Address      : %u\n", ntohs(arph->ar_hln));msg.content += std::string(tmp);
	sprintf(tmp, "   |-Length of Protocol Address      : %u\n", ntohs(arph->ar_pln));msg.content += std::string(tmp);
	sprintf(tmp, "   |-Opcode(command)      : %u\n", ntohs(arph->ar_op));msg.content += std::string(tmp);
	sprintf(tmp, "\n");msg.content += std::string(tmp);
	sprintf(tmp, "ARP Content\n");msg.content += std::string(tmp);
	sprintf(tmp, "   |-Sender Hardware Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",
			arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2], arp->arp_sha[3],
			arp->arp_sha[4], arp->arp_sha[5]);msg.content += std::string(tmp);
	sprintf(tmp, "   |-Sender Protocol Address      : %u.%u.%u.%u\n",
			arp->arp_spa[0], arp->arp_spa[1], arp->arp_spa[2], arp->arp_spa[3]);
	sprintf(tmp, "   |-Target Hardware Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",
			arp->arp_tha[0], arp->arp_tha[1], arp->arp_tha[2], arp->arp_tha[3],
			arp->arp_tha[4], arp->arp_tha[5]);msg.content += std::string(tmp);
	sprintf(tmp, "   |-Target Protocol Address      : %u.%u.%u.%u\n",
			arp->arp_tpa[0], arp->arp_tpa[1], arp->arp_tpa[2], arp->arp_tpa[3]);msg.content += std::string(tmp);
	sprintf(tmp, "\n");msg.content += std::string(tmp);
	sprintf(tmp,
		"                        DATA Dump                         ");msg.content += std::string(tmp);
	sprintf(tmp, "\n");msg.content += std::string(tmp);

	sprintf(tmp, "ARP Header\n");msg.content += std::string(tmp);
    msg.content += PrintData(Buffer + sizeof(struct ethhdr), sizeof(struct arphdr));

	sprintf(tmp, "ARP Payload\n");msg.content += std::string(tmp);    
	msg.content += PrintData(Buffer + sizeof(struct ethhdr) + sizeof(struct arphdr),
			Size - sizeof(struct ethhdr) - sizeof(struct arphdr));

    msg.srcip = "xx.xx.xx.xx";
    msg.desip = "xx.xx.xx.xx";
    msg.proto = 0x0608;

    //TODO emit
    emit newpack(msg);
}

void Core::print_ospf_packet(unsigned char *Buffer, int Size, int index)
{
	struct ospf_hdr *ospfhdr = (struct ospf_hdr *)(Buffer + sizeof(struct ethhdr)+
                                                    sizeof(struct iphdr));

	pack_dcp msg = print_ip_header(Buffer, Size, index);

    char tmp[256];
	sprintf(tmp, "\nOSPF Header\n");msg.content += std::string(tmp);
	sprintf(tmp, "   |-Version  : %d\n", ospfhdr->version);msg.content += std::string(tmp);
	switch (ospfhdr->type) {
	case 1:
		sprintf(tmp, "   |-Type     : hello(%d)\n", ospfhdr->type);msg.content += std::string(tmp);
		break;
	case 2:
		sprintf(tmp, "   |-Type     : database desciption(%d)\n", ospfhdr->type);msg.content += std::string(tmp);
		break;
	case 3:
		sprintf(tmp, "   |-Type     : lsr(%d)\n", ospfhdr->type);msg.content += std::string(tmp);
		break;
	case 4:
		sprintf(tmp, "   |-Type     : lsu(%d)\n", ospfhdr->type);msg.content += std::string(tmp);
		break;
	default:
		printf("unknown OSPF packet type (%d)\n", ospfhdr->type);msg.content += std::string(tmp);
	}
	sprintf(tmp, "   |-Length   : %d\n", ntohs(ospfhdr->len));msg.content += std::string(tmp);
	sprintf(tmp, "   |-rtr ID   : %d\n", ntohl(ospfhdr->rtr_id));msg.content += std::string(tmp);
	sprintf(tmp, "   |-Area ID  : %d\n", ntohl(ospfhdr->area_id));msg.content += std::string(tmp);
	sprintf(tmp, "   |-CheckSum : %d\n", ntohs(ospfhdr->chksum));msg.content += std::string(tmp);
	switch (ntohs(ospfhdr->auth_type)) {
	case 0:
		sprintf(tmp, "   |-AuthType : none(%d)\n", ntohs(ospfhdr->auth_type));msg.content += std::string(tmp);
		break;
	case 1:
	    sprintf(tmp, "   |-AuthType : simple(%d)\n", ntohs(ospfhdr->auth_type));msg.content += std::string(tmp);
	    sprintf(tmp, "   |-AuthKey  : see data dump\n");msg.content += std::string(tmp);
		break;
	case 2:
	    sprintf(tmp, "   |-AuthType : crypted(%d)\n", ntohs(ospfhdr->auth_type));msg.content += std::string(tmp);
	    sprintf(tmp, "   |-AuthKey  : see data dump\n");msg.content += std::string(tmp);
		break;
	}
	sprintf(tmp, "\n");msg.content += std::string(tmp);

	// TODO Add detailed type-specific headers and contents

	sprintf(tmp,
		"                        DATA Dump                         ");msg.content += std::string(tmp);
	sprintf(tmp, "\n");msg.content += std::string(tmp);

	sprintf(tmp, "OSPF Header\n");msg.content += std::string(tmp);
	msg.content += PrintData(Buffer + sizeof(struct ethhdr), sizeof(struct ospf_hdr));

	sprintf(tmp, "OSPF Payload\n");msg.content += std::string(tmp);
	msg.content += PrintData(Buffer + sizeof(struct ethhdr) + sizeof(struct ospf_hdr),
			Size - sizeof(struct ethhdr) - sizeof(struct ospf_hdr));
    

    // TODO emit
    msg.proto = 89;
    emit newpack(msg);
}

pack_dcp Core::print_ip_header(unsigned char *Buffer, int Size, int index)
{
	pack_dcp msg = print_ethernet_header(Buffer, Size, index);

	unsigned short iphdrlen;

	struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));

	iphdrlen = iph->ihl * 4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

    char tmp[256];
	sprintf(tmp, "\n");msg.content += std::string(tmp);
	sprintf(tmp, "IP Header\n");msg.content += std::string(tmp);
	sprintf(tmp, "   |-IP Version        : %d\n",
		(unsigned int)iph->version);msg.content += std::string(tmp);
	sprintf(tmp, "   |-IP Header Length  : %d DWORDS or %d Bytes\n",
		(unsigned int)iph->ihl, ((unsigned int)(iph->ihl)) * 4);msg.content += std::string(tmp);
	sprintf(tmp, "   |-Type Of Service   : %d\n",
		(unsigned int)iph->tos);msg.content += std::string(tmp);
	sprintf(tmp,
		"   |-IP Total Length   : %d  Bytes(Size of Packet)\n",
		ntohs(iph->tot_len));msg.content += std::string(tmp);msg.content += std::string(tmp);
	sprintf(tmp, "   |-Identification    : %d\n", ntohs(iph->id));msg.content += std::string(tmp);
	//sprintf(tmp , "   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
	//sprintf(tmp , "   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
	//sprintf(tmp , "   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
	sprintf(tmp, "   |-TTL      : %d\n", (unsigned int)iph->ttl);msg.content += std::string(tmp);
	sprintf(tmp, "   |-Protocol : %d\n", (unsigned int)iph->protocol);msg.content += std::string(tmp);
	sprintf(tmp, "   |-Checksum : %d\n", ntohs(iph->check));msg.content += std::string(tmp);
	sprintf(tmp, "   |-Source IP        : %s\n",
		inet_ntoa(source.sin_addr));msg.content += std::string(tmp);
	sprintf(tmp, "   |-Destination IP   : %s\n",
		inet_ntoa(dest.sin_addr));msg.content += std::string(tmp);

    msg.srcip = inet_ntoa(source.sin_addr);
    msg.desip = inet_ntoa(dest.sin_addr);
    msg.proto = 0x0008;
    return msg;
}

void Core::print_tcp_packet(unsigned char *Buffer, int Size, int index)
{
	unsigned short iphdrlen;

	struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));

	iphdrlen = iph->ihl * 4;

	struct tcphdr *tcph =
	    (struct tcphdr *)(Buffer + iphdrlen + sizeof(struct ethhdr));

	int header_size = sizeof(struct ethhdr) + iphdrlen + tcph->doff * 4;

	pack_dcp msg = print_ip_header(Buffer, Size, index);
    char tmp[256];

	sprintf(tmp, "\n");msg.content += std::string(tmp);
	sprintf(tmp, "TCP Header\n");msg.content += std::string(tmp);
	sprintf(tmp, "   |-Source Port      : %u\n", ntohs(tcph->source));msg.content += std::string(tmp);
	sprintf(tmp, "   |-Destination Port : %u\n", ntohs(tcph->dest));msg.content += std::string(tmp);
	sprintf(tmp, "   |-Sequence Number    : %u\n", ntohl(tcph->seq));msg.content += std::string(tmp);
	sprintf(tmp, "   |-Acknowledge Number : %u\n",
		ntohl(tcph->ack_seq));msg.content += std::string(tmp);
	sprintf(tmp, "   |-Header Length      : %d DWORDS or %d BYTES\n",
		(unsigned int)tcph->doff, (unsigned int)tcph->doff * 4);msg.content += std::string(tmp);
	//sprintf(tmp , "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
	//sprintf(tmp , "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
	sprintf(tmp, "   |-Urgent Flag          : %d\n",
		(unsigned int)tcph->urg);msg.content += std::string(tmp);
	sprintf(tmp, "   |-Acknowledgement Flag : %d\n",
		(unsigned int)tcph->ack);msg.content += std::string(tmp);
	sprintf(tmp, "   |-Push Flag            : %d\n",
		(unsigned int)tcph->psh);msg.content += std::string(tmp);
	sprintf(tmp, "   |-Reset Flag           : %d\n",
		(unsigned int)tcph->rst);msg.content += std::string(tmp);
	sprintf(tmp, "   |-Synchronise Flag     : %d\n",
		(unsigned int)tcph->syn);msg.content += std::string(tmp);
	sprintf(tmp, "   |-Finish Flag          : %d\n",
		(unsigned int)tcph->fin);msg.content += std::string(tmp);
	sprintf(tmp, "   |-Window         : %d\n", ntohs(tcph->window));msg.content += std::string(tmp);
	sprintf(tmp, "   |-Checksum       : %d\n", ntohs(tcph->check));msg.content += std::string(tmp);
	sprintf(tmp, "   |-Urgent Pointer : %d\n", tcph->urg_ptr);msg.content += std::string(tmp);
	sprintf(tmp, "\n");msg.content += std::string(tmp);
	sprintf(tmp,
		"                        DATA Dump                         ");msg.content += std::string(tmp);
	sprintf(tmp, "\n");msg.content += std::string(tmp);

	sprintf(tmp, "IP Header\n");msg.content += std::string(tmp);
	msg.content += PrintData(Buffer, iphdrlen);

	sprintf(tmp, "TCP Header\n");msg.content += std::string(tmp);
	msg.content += PrintData(Buffer + iphdrlen, tcph->doff * 4);

	sprintf(tmp, "Data Payload\n");msg.content += std::string(tmp);
	msg.content += PrintData(Buffer + header_size, Size - header_size); 
    msg.proto = 6;
    //TODO emit
    emit newpack(msg);
}

int is_dhcp_packet(int src_port, int dst_port, unsigned char *buf, int size)
{
    // easy check via ports
    if (src_port == 68 && dst_port == 67)
        return 1;
    else if (src_port == 67 && dst_port == 68)
        return 1;
    else
        return 0;
}

int is_rip_packet(int src_port, int dst_port, unsigned char *buf, int size)
{
    if (520 == src_port || 520 == dst_port)
        return 1;
    else
        return 0;
}

void Core::print_udp_packet(unsigned char *Buffer, int Size, int index)
{

	unsigned short iphdrlen;
	struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));

	iphdrlen = iph->ihl * 4;

	struct udphdr *udph =
	    (struct udphdr *)(Buffer + iphdrlen + sizeof(struct ethhdr));
	int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof udph;


	pack_dcp msg = print_ip_header(Buffer, Size, index);
    char tmp[256];

	sprintf(tmp, "\nUDP Header\n");msg.content += std::string(tmp);
	sprintf(tmp, "   |-Source Port      : %d\n", ntohs(udph->source));msg.content += std::string(tmp);
	sprintf(tmp, "   |-Destination Port : %d\n", ntohs(udph->dest));msg.content += std::string(tmp);
	sprintf(tmp, "   |-UDP Length       : %d\n", ntohs(udph->len));msg.content += std::string(tmp);
	sprintf(tmp, "   |-UDP Checksum     : %d\n", ntohs(udph->check));msg.content += std::string(tmp);

	sprintf(tmp, "\n");msg.content += std::string(tmp);
	sprintf(tmp, "IP Header\n");msg.content += std::string(tmp);
	msg.content += PrintData(Buffer, iphdrlen);

	sprintf(tmp, "UDP Header\n");msg.content += std::string(tmp);
	msg.content += PrintData(Buffer + iphdrlen, sizeof udph);

	sprintf(tmp, "Data Payload\n");msg.content += std::string(tmp);

	//Move the pointer ahead and reduce the size of string
	msg.content += PrintData(Buffer + header_size, Size - header_size);
    msg.proto = 17;

    //TODO emit
    emit newpack(msg);
}

void Core::print_dhcp_packet(unsigned char *Buffer, int Size, int index)
{
	unsigned short iphdrlen;
	struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));

	iphdrlen = iph->ihl * 4;

	struct udphdr *udph =
	    (struct udphdr *)(Buffer + iphdrlen + sizeof(struct ethhdr));
	int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof udph;
    struct dhcp_packet *dhcp =
        (struct dhcp_packet *)(Buffer + header_size);


    pack_dcp msg = print_ip_header(Buffer, Size, index);
    char tmp[256];

	sprintf(tmp, "\nUDP Header\n"); msg.content += std::string(tmp);
	sprintf(tmp, "   |-Source Port      : %d\n", ntohs(udph->source));msg.content += std::string(tmp);
	sprintf(tmp, "   |-Destination Port : %d\n", ntohs(udph->dest));msg.content += std::string(tmp);
	sprintf(tmp, "   |-UDP Length       : %d\n", ntohs(udph->len));msg.content += std::string(tmp);
	sprintf(tmp, "   |-UDP Checksum     : %d\n", ntohs(udph->check));msg.content += std::string(tmp);
	sprintf(tmp, "\n");msg.content += std::string(tmp);

	sprintf(tmp, "\nDHCP Content\n");msg.content += std::string(tmp);
    if (1 == dhcp->op)
        {sprintf(tmp, "   |-Operation      : c->s\n");msg.content += std::string(tmp);}
    else if (2 == dhcp->op)
        {sprintf(tmp, "   |-Operation      : s->c\n");msg.content += std::string(tmp);}
    else
        printf("bad dhcp packet\n");
    if (1 == dhcp->htype)
        {sprintf(tmp, "   |-Hardware Addr Type : Ethernet\n");msg.content += std::string(tmp);}
    else
        {sprintf(tmp, "   |-Hardware Addr Type : %d\n", dhcp->htype);msg.content += std::string(tmp);}
	sprintf(tmp, "   |-Hardware Addr Len  : %d\n", dhcp->hlen);msg.content += std::string(tmp);
	sprintf(tmp, "   |-Hops        : %d\n", dhcp->hops);msg.content += std::string(tmp);
	sprintf(tmp, "   |-Transac ID  : %d\n", ntohl(dhcp->xid));msg.content += std::string(tmp);
	sprintf(tmp, "   |-Duration    : %d\n", ntohs(dhcp->secs));msg.content += std::string(tmp);
	sprintf(tmp, "   |-Flags       : 0x%x\n", ntohs(dhcp->flags));msg.content += std::string(tmp);
	sprintf(tmp, "   |-Client IP Used : %s\n", inet_ntoa(dhcp->ciaddr));msg.content += std::string(tmp);
	sprintf(tmp, "   |-Client IP      : %s\n", inet_ntoa(dhcp->yiaddr));msg.content += std::string(tmp);
	sprintf(tmp, "   |-Next Server    : %s\n", inet_ntoa(dhcp->siaddr));msg.content += std::string(tmp);
	sprintf(tmp, "   |-Relay Agent    : %s\n", inet_ntoa(dhcp->giaddr));msg.content += std::string(tmp);
    if (1 == dhcp->op)  // we only know the len of hardware address is 48 in ethernet
        {sprintf(tmp, "   |-Client Hardware Addr  : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",
                dhcp->chaddr[0], dhcp->chaddr[1], dhcp->chaddr[2], dhcp->chaddr[3],
                dhcp->chaddr[4], dhcp->chaddr[5]);msg.content += std::string(tmp);}
	sprintf(tmp, "   |-Server Name    : %s\n", dhcp->sname);msg.content += std::string(tmp);
	sprintf(tmp, "   |-Boot Filename  : %s\n", dhcp->file);msg.content += std::string(tmp);
	sprintf(tmp, "   |-Options        : see dump data\n");msg.content += std::string(tmp);
	sprintf(tmp, "\n");msg.content += std::string(tmp);

	sprintf(tmp, "IP Header\n");msg.content += std::string(tmp);
	msg.content += PrintData(Buffer, iphdrlen);

	sprintf(tmp, "UDP Header\n");msg.content += std::string(tmp);
	msg.content += PrintData(Buffer + iphdrlen, sizeof udph);

	sprintf(tmp, "Data Payload\n");msg.content += std::string(tmp);

	//Move the pointer ahead and reduce the size of string
	msg.content += PrintData(Buffer + header_size, Size - header_size);
    msg.proto = 100;
    //TODO emit
    emit newpack(msg);
}

void Core::print_rip_packet(unsigned char *Buffer, int Size, int index)
{
	unsigned short iphdrlen;
	struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));

	iphdrlen = iph->ihl * 4;

	struct udphdr *udph =
	    (struct udphdr *)(Buffer + iphdrlen + sizeof(struct ethhdr));
	int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof udph;
    struct rip_packet *rip =
            (struct rip_packet *)(Buffer + header_size);

    char tmp[256];
	pack_dcp msg = print_ip_header(Buffer, Size, index);

	sprintf(tmp, "\nUDP Header\n");msg.content += std::string(tmp);
	sprintf(tmp, "   |-Source Port      : %d\n", ntohs(udph->source));msg.content += std::string(tmp);
	sprintf(tmp, "   |-Destination Port : %d\n", ntohs(udph->dest));msg.content += std::string(tmp);
	sprintf(tmp, "   |-UDP Length       : %d\n", ntohs(udph->len));msg.content += std::string(tmp);
	sprintf(tmp, "   |-UDP Checksum     : %d\n", ntohs(udph->check));msg.content += std::string(tmp);
	sprintf(tmp, "\n");msg.content += std::string(tmp);

	sprintf(tmp, "\nRIP Content\n");msg.content += std::string(tmp);
	sprintf(tmp, "   |-Command     : %d\n", rip->cmd);msg.content += std::string(tmp);
	sprintf(tmp, "   |-Version     : %d\n", rip->ver);msg.content += std::string(tmp);
    if (1 == rip->ver) {
	    sprintf(tmp, "   |-Addr Family : %d\n", ntohs(rip->u.v1.addr_family));msg.content += std::string(tmp);
	    sprintf(tmp, "   |-Address     : %s\n", inet_ntoa(*(struct in_addr *)&(rip->u.v1.addr)));msg.content += std::string(tmp);
	    sprintf(tmp, "   |-Metric      : %d\n", ntohl(rip->u.v1.metric));msg.content += std::string(tmp);
    } else if (2 == rip->ver) {
	    sprintf(tmp, "   |-Addr Format : %d\n", ntohs(rip->u.v2.addr_format));msg.content += std::string(tmp);
	    sprintf(tmp, "   |-Route Tag   : %d\n", ntohs(rip->u.v2.rt_tag));msg.content += std::string(tmp);
	    sprintf(tmp, "   |-Address     : %s\n", inet_ntoa(*(struct in_addr *)&(rip->u.v2.addr)));msg.content += std::string(tmp);
	    sprintf(tmp, "   |-Subnet Mask : %s\n", inet_ntoa(*(struct in_addr *)&(rip->u.v2.subnet_mask)));msg.content += std::string(tmp);
	    sprintf(tmp, "   |-Next Hop    : %s\n", inet_ntoa(*(struct in_addr *)&(rip->u.v2.nhop)));msg.content += std::string(tmp);
	    sprintf(tmp, "   |-Metric      : %d\n", ntohl(rip->u.v2.metric));msg.content += std::string(tmp);
    } else {
        printf("unknown version of rip\n");
    }
	sprintf(tmp, "\n");msg.content += std::string(tmp);

	sprintf(tmp, "IP Header\n");msg.content += std::string(tmp);
	msg.content += PrintData(Buffer, iphdrlen);

	sprintf(tmp, "UDP Header\n");msg.content += std::string(tmp);
	msg.content += PrintData(Buffer + iphdrlen, sizeof udph);

	sprintf(tmp, "Data Payload\n");msg.content += std::string(tmp);

	//Move the pointer ahead and reduce the size of string
	msg.content += PrintData(Buffer + header_size, Size - header_size);
    msg.proto = 101;
    //TODO emit
    emit newpack(msg);
}

void Core::process_udp_packet(unsigned char *Buffer, int Size, int index)
{
	unsigned short iphdrlen;
    int src_port, dst_port;
	struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));

	iphdrlen = iph->ihl * 4;

	struct udphdr *udph =
	    (struct udphdr *)(Buffer + iphdrlen + sizeof(struct ethhdr));
	src_port = ntohs(udph->source);
	dst_port = ntohs(udph->dest);

    if (is_dhcp_packet(src_port, dst_port, Buffer, Size)) {
        dhcp ++;
        this->print_dhcp_packet(Buffer, Size, index);
    } else if (is_rip_packet(src_port, dst_port, Buffer, Size)) {
        rip ++;
        this->print_rip_packet(Buffer, Size, index);
    } else
        this->print_udp_packet(Buffer, Size, index);
}

void Core::print_icmp_packet(unsigned char *Buffer, int Size, int index)
{
	unsigned short iphdrlen;

	struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));

	iphdrlen = iph->ihl * 4;

	struct icmphdr *icmph =
	    (struct icmphdr *)(Buffer + iphdrlen + sizeof(struct ethhdr));

	int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof icmph;

    char tmp[256];
	pack_dcp msg = print_ip_header(Buffer, Size, index);

	sprintf(tmp, "\n");msg.content+=std::string(tmp);

	sprintf(tmp, "ICMP Header\n");msg.content+=std::string(tmp);
	sprintf(tmp, "   |-Type : %d", (unsigned int)(icmph->type));msg.content+=std::string(tmp);

	if ((unsigned int)(icmph->type) == 11) {
		sprintf(tmp, "  (TTL Expired)\n");msg.content+=std::string(tmp);
	} else if ((unsigned int)(icmph->type) == ICMP_ECHOREPLY) {
		sprintf(tmp, "  (ICMP Echo Reply)\n");msg.content+=std::string(tmp);
	}

	sprintf(tmp, "   |-Code : %d\n", (unsigned int)(icmph->code));msg.content+=std::string(tmp);
	sprintf(tmp, "   |-Checksum : %d\n", ntohs(icmph->checksum));msg.content+=std::string(tmp);
	//sprintf(tmp , "   |-ID       : %d\n",ntohs(icmph->id));
	//sprintf(tmp , "   |-Sequence : %d\n",ntohs(icmph->sequence));
	sprintf(tmp, "\n");msg.content+=std::string(tmp);msg.content+=std::string(tmp);

	sprintf(tmp, "IP Header\n");msg.content+=std::string(tmp);msg.content+=std::string(tmp);
	msg.content += PrintData(Buffer, iphdrlen);

	sprintf(tmp, "UDP Header\n");msg.content+=std::string(tmp);
	msg.content += PrintData(Buffer + iphdrlen, sizeof icmph);

	sprintf(tmp, "Data Payload\n");msg.content+=std::string(tmp);

	//Move the pointer ahead and reduce the size of string
	msg.content += PrintData(Buffer + header_size, (Size - header_size));
    msg.proto = 1;
    //TODO emit
    emit newpack(msg);
}

std::string Core::PrintData(unsigned char *data, int Size)
{
	int i, j;

    char tmp[256];
	for (i = 0; i < Size; i++) {
		if (i != 0 && i % 16 == 0)	//if one line of hex printing is complete...
		{
			sprintf(tmp, "         ");
			for (j = i - 16; j < i; j++) {
				if (data[j] >= 32 && data[j] <= 128)
					sprintf(tmp, "%c", (unsigned char)data[j]);	//if its a number or alphabet

				else
					sprintf(tmp, ".");	//otherwise print a dot
			}
			sprintf(tmp, "\n");
		}

		if (i % 16 == 0)
			sprintf(tmp, "   ");
		sprintf(tmp, " %02X", (unsigned int)data[i]);

		if (i == Size - 1)	//print the last spaces
		{
			for (j = 0; j < 15 - i % 16; j++) {
				sprintf(tmp, "   ");	//extra spaces
			}

			sprintf(tmp, "         ");

			for (j = i - i % 16; j <= i; j++) {
				if (data[j] >= 32 && data[j] <= 128) {
					sprintf(tmp, "%c",
						(unsigned char)data[j]);
				} else {
					sprintf(tmp, ".");
				}
			}

			sprintf(tmp, "\n");
		}
	}
    return std::string(tmp);
}

void Core::handle_switch(std::string adpt){
    if (!this->running){
        this->intf = adpt;
        this->running = true;
        this->start();
    }else{
        this->running = false;
        this->quit();
    }
}
