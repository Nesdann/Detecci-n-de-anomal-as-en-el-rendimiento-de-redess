#include <pcap.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <pcap.h>
#include "flow.h"
#include "flow_table.h"
#include "time_utils.h"
#include "features.h"

static struct timeval last_expire = {0};


void on_packet(u_char *args,
               const struct pcap_pkthdr *header,
               const u_char *packet)
{
    const struct ip *ip_hdr;
    const struct tcphdr *tcp_hdr;
    const struct udphdr *udp_hdr;

    flow_t flow = {0};

    // Saltear Ethernet (14 bytes)
    ip_hdr = (struct ip *)(packet + 14);

    if (ip_hdr->ip_v != 4)
        return;

    flow.key.src_ip = ip_hdr->ip_src.s_addr;
    flow.key.dst_ip = ip_hdr->ip_dst.s_addr;
    flow.key.proto  = ip_hdr->ip_p;

    if (flow.key.proto == IPPROTO_TCP) {
        tcp_hdr = (struct tcphdr *)((u_char *)ip_hdr + ip_hdr->ip_hl * 4);
        flow.key.src_port = ntohs(tcp_hdr->th_sport);
        flow.key.dst_port = ntohs(tcp_hdr->th_dport);

    } else if (flow.key.proto == IPPROTO_UDP) {
        udp_hdr = (struct udphdr *)((u_char *)ip_hdr + ip_hdr->ip_hl * 4);
        flow.key.src_port = ntohs(udp_hdr->uh_sport);
        flow.key.dst_port = ntohs(udp_hdr->uh_dport);

    } else {
        return;
    }

    flow.packets = 1;
    flow.bytes   = header->len;
    flow.first_seen = header->ts;
    flow.last_seen  = header->ts;

    // Debug: imprimir
    printf("Flow:\n");
    printf("  %s:%u -> %s:%u proto=%u bytes=%lu\n",
           inet_ntoa(*(struct in_addr *)&flow.key.src_ip),
           flow.key.src_port,
           inet_ntoa(*(struct in_addr *)&flow.key.dst_ip),
           flow.key.dst_port,
           flow.key.proto,
           flow.bytes);

    flow_table_t *table = (flow_table_t *)args;

    flow_table_get_or_create(table,
                             &flow.key,
                             &header->ts,
                             header->len);
    
    if (last_expire.tv_sec == 0) {
        last_expire = header->ts;
    }

    double since =
        timeval_diff(header->ts, last_expire);

    if (since >= EXPIRE_INTERVAL) {
        flow_table_expire(table, &header->ts);
        last_expire = header->ts;
    }

}


int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    flow_table_t table;
    flow_table_init(&table);

<<<<<<< HEAD
    handle = pcap_open_live("en0", 65535, 1, 1000, errbuf);
=======
    

    

    handle = pcap_open_live("enp5s0", 65535, 1, 1000, errbuf);//!!! posible para cambiar
>>>>>>> fe48c2de01142341d7b193a0211019cac793ef1c
    if (!handle) {
        fprintf(stderr, "pcap error: %s\n", errbuf);
        return 1;
    }

    pcap_loop(handle, 10000, on_packet, (u_char *)&table);
    flow_table_dump(&table);

    pcap_close(handle);
    return 0;
}
