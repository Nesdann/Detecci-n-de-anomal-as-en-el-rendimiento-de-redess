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
#include <signal.h>

pcap_t *handle_global = NULL; // Para poder cerrarlo desde el signal handler

void handle_sigint(int sig) {
    if (handle_global) {
        pcap_breakloop(handle_global); // Detiene el loop
    }
}


static struct timeval last_expire = {0};


void on_packet(u_char *args,
               const struct pcap_pkthdr *header,
               const u_char *packet)
{
    const struct ip *ip_hdr;
    const struct tcphdr *tcp_hdr;
    const struct udphdr *udp_hdr;
    flow_t * f;

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
    //printf("Flowh:\n");
    /*printf("  %s:%u -> %s:%u proto=%u bytes=%lu\n",
           inet_ntoa(*(struct in_addr *)&flow.key.src_ip),
           flow.key.src_port,
           inet_ntoa(*(struct in_addr *)&flow.key.dst_ip),
           flow.key.dst_port,
           flow.key.proto,
           flow.bytes);*/

    flow_table_t *table = (flow_table_t *)args;
    //printf("KEY/RAW antes del get or crate: %u -> %u\n", flow.key.src_ip, flow.key.dst_ip);

    f=flow_table_get_or_create(table,
                             &flow.key,
                             &header->ts,
                             header->len);

    if (flow.key.src_ip == f->initiator_ip &&
    flow.key.src_port == f->initiator_port) {

         f->fwd_packets++;
         f->fwd_bytes += header->len;

    } else {

         f->bwd_packets++;
          f->bwd_bytes += header->len;
}

    if (flow.key.proto == IPPROTO_TCP) {
    if (tcp_hdr->th_flags & TH_SYN)
        f->syn_count++;

    if (tcp_hdr->th_flags & TH_ACK)
        f->ack_count++;

    if (tcp_hdr->th_flags & TH_FIN)
        f->fin_count++;

    if (tcp_hdr->th_flags & TH_RST)
        f->rst_count++;
}

    //printf("packets antes de flow update,despeus del get or crate: %lu\n", f->packets);
    /*printf("ts: %ld.%06ld  last: %ld.%06ld\n",
           header->ts.tv_sec, header->ts.tv_usec,
           f->last_seen.tv_sec, f->last_seen.tv_usec);*/

    flow_update(f,header->ts,header->len);
    
    if (last_expire.tv_sec == 0) {
        last_expire = header->ts;
    }

    double since =
        timeval_diff(header->ts, last_expire);
    //printf("since last expire: %.2f seconds\n", since);
    struct timeval real_now;
gettimeofday(&real_now, NULL);

//printf("REAL: %ld.%06ld\n", real_now.tv_sec, real_now.tv_usec);
//printf("PKT : %ld.%06ld\n", header->ts.tv_sec, header->ts.tv_usec);
//printf(">>> EXPIRE CHECK\n");
    if (since >= EXPIRE_INTERVAL) {
        flow_table_expire(table, &header->ts);
        last_expire = header->ts;
    }

}


int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    flow_table_t table;
    flow_table_init(&table);

    // 1. Aumentamos el buffer de pcap para ráfagas de Nmap
    // Usamos pcap_create y pcap_activate para tener más control
    handle_global = pcap_create("enp5s0", errbuf);
    if (!handle_global) {
        fprintf(stderr, "pcap_create error: %s\n", errbuf);
        return 1;
    }

    pcap_set_snaplen(handle_global, 65535);
    pcap_set_promisc(handle_global, 1);
    pcap_set_timeout(handle_global, 1000);
    pcap_set_buffer_size(handle_global, 10 * 1024 * 1024); // 10MB de buffer para no perder paquetes
    pcap_activate(handle_global);

    // 2. Configurar el manejador de Ctrl+C
    signal(SIGINT, handle_sigint);

    printf("Sniffer activo. Capturando en enp5s0... (Presione Ctrl+C para finalizar y exportar)\n");

    // 3. El loop (on_packet NO debe tener printfs internos para ser veloz)
    pcap_loop(handle_global, -1, on_packet, (u_char *)&table);

    // 4. Al salir del loop (por Ctrl+C), mostrar estadísticas y DUMP FINAL
    struct pcap_stat stats;
    if (pcap_stats(handle_global, &stats) >= 0) {
        printf("\n--- Estadísticas Finales ---\n");
        printf("  Paquetes recibidos: %u\n", stats.ps_recv);
        printf("  Paquetes perdidos (drop): %u\n", stats.ps_drop);
    }

    printf("\nExportando flujos restantes en memoria...\n");
    // Forzamos un expire de todo o un dump total
    flow_table_dump(&table); 
    //fun de final para exportar lo que quede en memoria, aunque no haya expirado
    flow_table_expire_all(&table);
    pcap_close(handle_global);
    return 0;
}