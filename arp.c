/**
 * @author lijk@infosec.com.cn
 * @version 0.0.1
 * @date 2018-8-22 15:35:23
**/
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>

#define MAX_PACKET_SIZE (14+28+18)

struct arp_hdr
{
    unsigned short  ar_hrd;
    unsigned short  ar_pro;
    unsigned char   ar_hln;
    unsigned char   ar_pln;
    unsigned short  ar_op;

    unsigned char   ar_sha[ETH_ALEN];
    unsigned char   ar_sip[4];
    unsigned char   ar_tha[ETH_ALEN];
    unsigned char   ar_tip[4];
};

static int ipv4_arp_request(int fd, char *device, char *ip)
{
    int ret = 0;
    unsigned char packet[MAX_PACKET_SIZE-18] = {0};
    struct ethhdr *ethhdr = (struct ethhdr*)packet;
    struct arp_hdr *arphdr = (struct arp_hdr*)(packet + 14);

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(struct ifreq));

    struct sockaddr_ll addr;
    socklen_t len = sizeof(struct sockaddr_ll);
    memset(&addr, 0, sizeof(struct sockaddr_ll));

    int index = 0;
    unsigned char sip[4] = {0};
    unsigned char smac[ETH_ALEN] = {0};
    in_addr_t dip = inet_addr(ip);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, device, IFNAMSIZ-1);

    // index
    if(ioctl(fd, SIOCGIFINDEX, &ifr) < 0)
    {
        fprintf(stderr, "%s %s:%u - ipv4 ioctl failed %d: %s\n", __FUNCTION__, __FILE__, __LINE__, errno, strerror(errno));
        return -1;
    }
    index = ifr.ifr_ifindex;

    // mac
    if(ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)
    {
        fprintf(stderr, "%s %s:%u - ipv4 ioctl failed %d: %s\n", __FUNCTION__, __FILE__, __LINE__, errno, strerror(errno));
        return -1;
    }
    memcpy(smac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    // ip
    if(ioctl(fd, SIOCGIFADDR, &ifr) < 0)
    {
        fprintf(stderr, "%s %s:%u - ipv4 ioctl failed - %d: %s\n", __FUNCTION__, __FILE__, __LINE__, errno, strerror(errno));
        return -1;
    }
    memcpy(sip, &((struct sockaddr_in*)&(ifr.ifr_addr))->sin_addr.s_addr, 4);

    // struct sockaddr_ll
    addr.sll_family     = AF_PACKET;
    addr.sll_ifindex    = index;

    // struct ethhdr
    memset(ethhdr->h_dest, 0xff, ETH_ALEN);
    memcpy(ethhdr->h_source, smac, ETH_ALEN);
    ethhdr->h_proto     = htons(ETH_P_ARP);

    // struct arphdr
    arphdr->ar_hrd      = htons(ARPHRD_ETHER);
    arphdr->ar_pro      = htons(ETH_P_IP);
    arphdr->ar_hln      = ETH_ALEN;
    arphdr->ar_pln      = 4;
    arphdr->ar_op       = htons(ARPOP_REQUEST);
    memcpy(arphdr->ar_sha, smac, ETH_ALEN);
    memcpy(arphdr->ar_sip, sip, 4);
    memset(arphdr->ar_tha, 0x00, ETH_ALEN);
    memcpy(arphdr->ar_tip, &dip, 4);

    ret = sendto(fd, packet, MAX_PACKET_SIZE-18, 0, (struct sockaddr*)&addr, len);
    if(ret < 0)
    {
        fprintf(stderr, "%s %s:%u - ipv4 send arp broadcast to \"%s\" failed - %d: %s\n", __FUNCTION__, __FILE__, __LINE__, ip, errno, strerror(errno));
        return -1;
    }

    fprintf(stdout, "%s %s:%u - ipv4 send arp broadcast to \"%s\" succeed\n", __FUNCTION__, __FILE__, __LINE__, ip);
    return 0;
}

static int ipv4_arp_response(int fd, char *ip)
{
    int length = 0;
    unsigned char packet[MAX_PACKET_SIZE] = {0};

    struct sockaddr_ll addr;
    socklen_t len = sizeof(struct sockaddr_ll);
    memset(&addr, 0, sizeof(struct sockaddr_ll));

    length = recvfrom(fd, packet, MAX_PACKET_SIZE, 0, (struct sockaddr*)&addr , &len);
    if(length <= 0)
    {
        fprintf(stderr, "%s %s:%u -  ipv4 recv arp repley from \"%s\" failed - %d: %s\n", __FUNCTION__, __FILE__, __LINE__, ip, errno, strerror(errno));
        return -1;
    }

    struct ethhdr *ethhdr = (struct ethhdr*)packet;
    if(ntohs(ethhdr->h_proto) != ETH_P_ARP)
    {
        fprintf(stderr, "%s %s:%u - ipv4 arp repley from \"%s\" ethhdr format error\n", __FUNCTION__, __FILE__, __LINE__, ip);
        return -1;
    }
    struct arp_hdr *arphdr = (struct arp_hdr*)(packet + 14);
    if(ntohs(arphdr->ar_hrd) != ARPHRD_ETHER || ntohs(arphdr->ar_pro) != ETH_P_IP || ntohs(arphdr->ar_op) != ARPOP_REPLY)
    {
        fprintf(stderr, "%s %s:%u - ipv4 arp repley from \"%s\" arphdr format error\n", __FUNCTION__, __FILE__, __LINE__, ip);
        return -1;
    }

    fprintf(stdout, "%s %s:%u - ipv4 recv arp repley from \"%s\" succeed\n", __FUNCTION__, __FILE__, __LINE__, ip);
    return 0;
}

static int ipv4_arp(char *device, char *ip)
{
    int fd = 0;
    int ret = 0;

    struct sockaddr_ll addr;
    socklen_t len = sizeof(struct sockaddr_ll);
    memset(&addr, 0, sizeof(struct sockaddr_ll));

    fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(fd < 0)
    {
        fprintf(stderr, "%s %s:%u - ipv4 socket failed - %d: %s\n", __FUNCTION__, __FILE__, __LINE__, errno, strerror(errno));
        return -1;
    }

    addr.sll_family     = AF_PACKET;
    addr.sll_ifindex    = if_nametoindex(device);
    if(bind(fd, (struct sockaddr*)&addr , len) < 0)
    {
        fprintf(stderr, "%s %s:%u - ipv4 bind failed - %d: %s\n", __FUNCTION__, __FILE__, __LINE__, errno, strerror(errno));
        return -1;
    }

    ret = ipv4_arp_request(fd, device, ip);
    if(ret < 0)
    {
        fprintf(stderr, "%s %s:%u - ipv4 arp request failed - %d: %s\n", __FUNCTION__, __FILE__, __LINE__, errno, strerror(errno));
        goto ErrP;
    }

    int i = 0;
    int num = 0;
    int timeout = 1000;
    unsigned int nfds = 1;
    struct pollfd fds[1];
    fds[0].fd = fd;
    fds[0].events = POLLIN;
    fds[0].revents = 0;

    num = poll(fds, nfds, timeout);
    if(num <= 0)
    {
        fprintf(stderr, "%s %s:%u - ipv4 poll failed - %d: %s\n", __FUNCTION__, __FILE__, __LINE__, errno, strerror(errno));
        goto ErrP;
    }

    for(i = 0; i < nfds; i++)
    {
        if(fds[i].revents & POLLIN)
        {
            ret = ipv4_arp_response(fd, ip);
            if(ret < 0)
            {
                fprintf(stderr, "%s %s:%u - ipv4 arp response failed - %d: %s\n", __FUNCTION__, __FILE__, __LINE__, errno, strerror(errno));
                goto ErrP;
            }
        }
    }

    if(fd > 0) close(fd);
    return 0;
ErrP:
    if(fd > 0) close(fd);
    return -1;
}

int main(int argc, char *argv[])
{
    return ipv4_arp("eth0", "192.168.1.250");
}
