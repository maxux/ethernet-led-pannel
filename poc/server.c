#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>

const uint8_t dstaddr[] = {
    0xA2, 0x43, 0x42, 0x42, 0x42, 0x01
};

#define DEFAULT_IF	"bond0"
#define BUF_SIZ		1024

int main() {
	int sockfd;
	struct ifreq if_idx;
	struct ifreq if_mac;
	int tx_len = 0;
	char sendbuf[BUF_SIZ];
	struct ether_header *eh = (struct ether_header *) sendbuf;
	struct iphdr *iph = (struct iphdr *) (sendbuf + sizeof(struct ether_header));
	struct sockaddr_ll socket_address;
	char ifName[IFNAMSIZ];

    strcpy(ifName, DEFAULT_IF);

	if((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
	    perror("socket");
        exit(EXIT_FAILURE);
    }

	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
	if(ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
	    perror("SIOCGIFINDEX");

	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
	if(ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
	    perror("SIOCGIFHWADDR");

	memset(sendbuf, 0, BUF_SIZ);

    memcpy(eh->ether_shost, if_mac.ifr_hwaddr.sa_data, 6);
    memcpy(eh->ether_dhost, dstaddr, 6);

	eh->ether_type = 0xb688;
	tx_len += sizeof(struct ether_header);

	sendbuf[tx_len++] = 0x00;
	sendbuf[tx_len++] = 0xff;
	sendbuf[tx_len++] = 0xff;

	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	socket_address.sll_halen = ETH_ALEN;

	memcpy(socket_address.sll_addr, dstaddr, 6);

	if(sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
	    perror("send");

	return 0;
}
