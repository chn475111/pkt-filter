/**
 * @author lijk@.infosec.com.cn
 * @version 0.0.1
 * @date 2016-6-1 11:50:10
 */
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <libgen.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>

static void dump_packet_fp(FILE *fp, unsigned char *packet, unsigned int packet_len)
{
    int i, j;

    if(!packet || packet_len <= 0)
        return;

    for (i = 0; i < packet_len; i++) {
        if (i % 16 == 0) fprintf( fp, "  ");

        fprintf( fp, "%02x ", packet[i]);

        if ((i + 1) % 16 == 0) {
            fprintf( fp, "  ");
            for (j = 0; j <= i % 16; j++) {
                unsigned char c;

                if (i-15+j >= packet_len) break;

                c = packet[i-15+j];

                fprintf( fp, "%c", c > 32 && c < 128 ? c : '.');
            }

            fprintf( fp, "\n");
        }
    }

    if (packet_len % 16 != 0) {
        for (j = i % 16; j < 16; j++) {
            fprintf( fp, "   ");
        }

        fprintf( fp, "  ");
        for (j = i & ~0xf; j < packet_len; j++) {
            unsigned char c;

            c = packet[j];
            fprintf( fp, "%c", c > 32 && c < 128 ? c : '.');
        }
        fprintf( fp, "\n");
    }
}

/*
    struct pcap_pkthdr
    {
        struct timeval ts;  time stamp
        bpf_u_int32 caplen; length of portion present
        bpf_u_int32 len;    length this packet (off wire)
    };
*/
static void pcap_cb(unsigned char *user, const struct pcap_pkthdr *hdr, const unsigned char *data)
{
    int *cnt = (int *)user;
    char src_ip[INET_ADDRSTRLEN+1] = {0}, dst_ip[INET_ADDRSTRLEN+1] = {0};

    fprintf(stdout, "cnt: %d\n", ++(*cnt));
    fprintf(stdout, "--------------------------------\n");

    struct ethhdr *eth_hdr = (struct ethhdr*)data;
    if(eth_hdr == NULL) return;
    uint8_t eth_hdrlen = sizeof(struct ethhdr);     //ETH包头长度: 14

    fprintf(stdout, "eth proto: %hu\n", ntohs(eth_hdr->h_proto));
    fprintf(stdout, "src_mac: %02x:%02x:%02x:%02x:%02x:%02x ", eth_hdr->h_source[0], eth_hdr->h_source[1], eth_hdr->h_source[2], eth_hdr->h_source[3], eth_hdr->h_source[4], eth_hdr->h_source[5]);
    fprintf(stdout, "-> ");
    fprintf(stdout, "dst_mac: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_hdr->h_dest[0], eth_hdr->h_dest[1], eth_hdr->h_dest[2], eth_hdr->h_dest[3], eth_hdr->h_dest[4], eth_hdr->h_dest[5]);

    struct iphdr *ip_hdr = (struct iphdr *)(hdr->len > eth_hdrlen ? data + eth_hdrlen : NULL);
#if 1
    if(ntohs(eth_hdr->h_proto) != ETH_P_IP || ip_hdr == NULL) return;
#else
    if(ntohs(eth_hdr->h_proto) != ETH_P_IPV6 || ipv6_hdr == NULL) return;
#endif
    uint8_t ip_hdrlen = ip_hdr->ihl*4;              //IP包头长度
    uint16_t ip_totlen = ntohs(ip_hdr->tot_len);    //IP包总长度

    inet_ntop(AF_INET, &ip_hdr->saddr, src_ip, INET_ADDRSTRLEN+1);
    inet_ntop(AF_INET, &ip_hdr->daddr, dst_ip, INET_ADDRSTRLEN+1);
    fprintf(stdout, "ip proto: %hhu\n", ip_hdr->protocol);
    fprintf(stdout, "src_ip: %s ", src_ip);
    fprintf(stdout, "-> ");
    fprintf(stdout, "dst_ip: %s\n", dst_ip);

    if(ip_hdr->protocol == IPPROTO_ICMP)
    {
        struct icmphdr *icmp_hdr = (struct icmphdr*)(data + eth_hdrlen + ip_hdrlen);
        uint8_t icmp_hdrlen = sizeof(struct icmphdr);               //ICMP包头长度
        uint16_t icmp_bdylen = ip_totlen - ip_hdrlen - icmp_hdrlen; //ICMP包体长度

        fprintf(stdout, "type: %hhu ", icmp_hdr->type);
        fprintf(stdout, "code: %hhu ", icmp_hdr->code);
        fprintf(stdout, "checksum: %hu\n", ntohs(icmp_hdr->checksum));

        dump_packet_fp(stdout, (unsigned char*)(data + eth_hdrlen + ip_hdrlen + icmp_hdrlen), icmp_bdylen);
    }
    else if(ip_hdr->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcp_hdr = (struct tcphdr*)(data + eth_hdrlen + ip_hdrlen);
        uint8_t tcp_hdrlen = tcp_hdr->doff*4;                       //TCP包头长度
        uint16_t tcp_bdylen = ip_totlen - ip_hdrlen - tcp_hdrlen;   //TCP包体长度

        fprintf(stdout, "src_port: %hu ", ntohs(tcp_hdr->source));
        fprintf(stdout, "-> ");
        fprintf(stdout, "dst_port: %hu\n", ntohs(tcp_hdr->dest));

        dump_packet_fp(stdout, (unsigned char*)(data + eth_hdrlen + ip_hdrlen + tcp_hdrlen), tcp_bdylen);
    }
    else if(ip_hdr->protocol == IPPROTO_UDP)
    {
        struct udphdr *udp_hdr = (struct udphdr*)(data + eth_hdrlen + ip_hdrlen);
        uint8_t udp_hdrlen = sizeof(struct udphdr);                 //UDP包头长度: 8
        uint16_t udp_totlen = ntohs(udp_hdr->len);                  //UDP包总长度

        fprintf(stdout, "src_port: %hu ", ntohs(udp_hdr->source));
        fprintf(stdout, "-> ");
        fprintf(stdout, "dst_port: %hu\n", ntohs(udp_hdr->dest));

        dump_packet_fp(stdout, (unsigned char*)(data + eth_hdrlen + ip_hdrlen + udp_hdrlen), udp_totlen - udp_hdrlen);
    }
    else
    {
        fprintf(stdout, "unknown ip packet\n");
        dump_packet_fp(stdout, (unsigned char*)(data + eth_hdrlen + ip_hdrlen), ip_totlen - ip_hdrlen);
    }

    fprintf(stdout, "--------------------------------\n");
}

static char* copy_argv(register char **argv)
{
    register char **p;
    register u_int len = 0;
    char *buf;
    char *src, *dst;

    p = argv;
    if (*p == 0)
        return NULL;

    while (*p)
        len += strlen(*p++) + 1;

    buf = (char *)malloc(len);
    if (buf == NULL)
        return NULL;

    p = argv;
    dst = buf;
    while ((src = *p++) != NULL) {
        while ((*dst++ = *src++) != '\0')
            ;
        dst[-1] = ' ';
    }
    dst[-1] = '\0';

    return buf;
}

int main(int argc, char *argv[])
{
    int c = 0, option_index = 0;
    int daimon = 0;
    char *device = "eth0";
    char *readfile = NULL;
    char ebuf[PCAP_ERRBUF_SIZE+1] = {0};
    pcap_t *pd = NULL;
    bpf_u_int32 localnet = PCAP_NETMASK_UNKNOWN, netmask = PCAP_NETMASK_UNKNOWN;
    char net[INET_ADDRSTRLEN+1] = {0}, mask[INET_ADDRSTRLEN+1] = {0};
    struct bpf_program fcode;
    char *cmdbuf = NULL;
    int status = 0;
    static int packet_count = 0;

    static struct option long_options[] = 
    {
        {"interface", required_argument, NULL, 'i'},
        {"readfile", required_argument, NULL, 'r'},
        {"daemon", no_argument, NULL, 'd'},
        {"help", no_argument, NULL, 'h'},
        {0,0,0,0}
    };

    opterr = 0;
    while((c = getopt_long(argc, argv, "i:r:dh", long_options, &option_index)) != -1)
    {
        switch(c)
        {
            case 'i':
                device = optarg;
                break;
            case 'r':
                readfile = optarg;
                break;
            case 'd':
                daimon = 1;
                break;
            case 'h':
                fprintf(stdout, "Usage:\n");
                fprintf(stdout, "-i, --interface <device>, default is: \"%s\"\n", device);
                fprintf(stdout, "-r, --readfile <pcap>\n");
                fprintf(stdout, "-d, --daemon\n");
                fprintf(stdout, "-h, --help\n");
                exit(EXIT_SUCCESS);
                break;
            default:
                fprintf(stderr, "Usage:\n");
                fprintf(stderr, "-i, --interface <device>, default is: \"%s\"\n", device);
                fprintf(stderr, "-r, --readfile <pcap>\n");
                fprintf(stderr, "-d, --daemon\n");
                fprintf(stderr, "-h, --help\n");
                exit(EXIT_FAILURE);
                break;
        }
    }

    char *program_name = basename(argv[0]);
    if(daimon)
        daemon(0, 0);

    if(readfile)
    {
        access(readfile, R_OK);
        pd = pcap_open_offline(readfile, ebuf);
        if(pd == NULL)
        {
            fprintf(stderr, "pcap_open_offline: %s\n", ebuf);
            return -1;
        }
    }
    else
    {
        if(device == NULL)
        {
            device = pcap_lookupdev(ebuf);
            if(device == NULL)
            {
                fprintf(stderr, "pcap_lookupdev: %s\n", ebuf);
                return -1;
            }
        }

        pd = pcap_open_live(device, 65535, 0, 1000, ebuf);
        if(pd == NULL)
        {
            fprintf(stderr, "pcap_open_live: %s\n", ebuf);
            return -1;
        }

        if(pcap_lookupnet(device, &localnet, &netmask, ebuf) < 0)
        {
            fprintf(stderr, "pcap_lookupnet: %s\n", ebuf);
            goto ErrP;
        }
        if(inet_ntop(AF_INET, &localnet, net, INET_ADDRSTRLEN+1))
            fprintf(stdout, "net: %s\n", net);
        if(inet_ntop(AF_INET, &netmask, mask, INET_ADDRSTRLEN+1))
            fprintf(stdout, "mask: %s\n", mask);
    }

    cmdbuf = copy_argv(&argv[optind]);
    if(pcap_compile(pd, &fcode, cmdbuf, 1, netmask) < 0)
    {
        fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(pd));
        goto ErrP;
    }
    if(pcap_setfilter(pd, &fcode) < 0)
    {
        fprintf(stderr, "pcap_setfilter: %s\n", pcap_geterr(pd));
        goto ErrP;
    }
    pcap_freecode(&fcode);

    if(readfile)
    {
        while(true)
        {
            status = pcap_dispatch(pd, -1, pcap_cb, (unsigned char *)&packet_count);
            if(status <= 0)
            {
                if(status != 0) fprintf(stderr, "pcap_dispatch: %s\n", pcap_geterr(pd));
                break;
            }
        }
    }
    else
    {
        while(true)
        {
            status = pcap_dispatch(pd, -1, pcap_cb, (unsigned char *)&packet_count);
            if(status < 0)
            {
                fprintf(stderr, "pcap_dispatch: %s\n", pcap_geterr(pd));
                break;
            }
        }
    }

    fprintf(stdout, "%s: succeed\n", program_name);
    if(cmdbuf) free(cmdbuf);
    if(pd) pcap_close(pd);
    exit(EXIT_SUCCESS);
ErrP:
    fprintf(stderr, "%s: failed\n", program_name);
    if(cmdbuf) free(cmdbuf);
    if(pd) pcap_close(pd);
    exit(EXIT_FAILURE);
}
