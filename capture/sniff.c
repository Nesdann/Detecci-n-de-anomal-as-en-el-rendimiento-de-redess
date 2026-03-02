#include <pcap.h>
#include <stdio.h>
#include <fcntl.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include "flow.h"
#include "flow_table.h"
#include "time_utils.h"
#include "features.h"
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

pcap_t *handle_global = NULL;

void handle_sigint(int sig)
{
    if (handle_global)
    {
        pcap_breakloop(handle_global);
    }
}

static struct timeval last_expire = {0};

void on_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    const struct ip *ip_hdr;
    const struct tcphdr *tcp_hdr;
    const struct udphdr *udp_hdr;
    flow_t *f;
    flow_t flow = {0};

    ip_hdr = (struct ip *)(packet + 14);
    if (ip_hdr->ip_v != 4)
        return;

    flow.key.src_ip = ip_hdr->ip_src.s_addr;
    flow.key.dst_ip = ip_hdr->ip_dst.s_addr;
    flow.key.proto = ip_hdr->ip_p;

    if (flow.key.proto == IPPROTO_TCP)
    {
        tcp_hdr = (struct tcphdr *)((u_char *)ip_hdr + ip_hdr->ip_hl * 4);
        flow.key.src_port = ntohs(tcp_hdr->th_sport);
        flow.key.dst_port = ntohs(tcp_hdr->th_dport);
    }
    else if (flow.key.proto == IPPROTO_UDP)
    {
        udp_hdr = (struct udphdr *)((u_char *)ip_hdr + ip_hdr->ip_hl * 4);
        flow.key.src_port = ntohs(udp_hdr->uh_sport);
        flow.key.dst_port = ntohs(udp_hdr->uh_dport);
    }
    else
    {
        return;
    }

    flow.packets = 1;
    flow.bytes = header->len;
    flow.first_seen = header->ts;
    flow.last_seen = header->ts;

    flow_table_t *table = (flow_table_t *)args;
    f = flow_table_get_or_create(table, &flow.key, &header->ts, header->len);

    if (flow.key.src_ip == f->initiator_ip && flow.key.src_port == f->initiator_port)
    {
        f->fwd_packets++;
        f->fwd_bytes += header->len;
    }
    else
    {
        f->bwd_packets++;
        f->bwd_bytes += header->len;
    }

    if (flow.key.proto == IPPROTO_TCP)
    {
        if (tcp_hdr->th_flags & TH_SYN)
            f->syn_count++;
        if (tcp_hdr->th_flags & TH_ACK)
            f->ack_count++;
        if (tcp_hdr->th_flags & TH_FIN)
            f->fin_count++;
        if (tcp_hdr->th_flags & TH_RST)
            f->rst_count++;
    }

    flow_update(f, header->ts, header->len);

    if (last_expire.tv_sec == 0)
        last_expire = header->ts;

    double since = timeval_diff(header->ts, last_expire);
    if (since >= EXPIRE_INTERVAL)
    {
        flow_table_expire(table, &header->ts);
        last_expire = header->ts;
    }
}

int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    flow_table_t table;
    flow_table_init(&table);

    // Ruta relativa para que le funcione a tu amigo
    const char *PIPE_REL_PATH = "../ids_pipe";

    handle_global = pcap_open_live("enp5s0", 65535, 1, 1000, errbuf);//NF
    if (!handle_global)
    {
        fprintf(stderr, "Error abriendo interfaz en0: %s\n", errbuf);
        return 1;
    }

    signal(SIGINT, handle_sigint);

    printf("Sentinel Sniffer activo en enp5s0...\n");

    // 1. Crear el pipe si no existe (con permisos 0666)
    if (mkfifo(PIPE_REL_PATH, 0666) == -1)
    {
        if (errno != EEXIST)
        {
            perror("❌ Error al crear el pipe");
        }
    }

    printf("🧪 Probando conexión con Python en %s...\n", PIPE_REL_PATH);

    // 2. Intentar abrirlo. OJO: open en un pipe se bloquea hasta que Python lo abra para leer.
    // Por eso, primero corre el script de Python!
    int fd_test = open(PIPE_REL_PATH, O_WRONLY);

    if (fd_test != -1)
    {
        const char *test_msg = "TEST,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0\n";
        write(fd_test, test_msg, 68);
        close(fd_test);
        printf("✅ Conexión inicial exitosa. Iniciando captura...\n");
    }
    else
    {
        perror("❌ ERROR CRÍTICO: No se pudo abrir el pipe");
        printf("Asegúrate de que Python (main.py) esté corriendo ANTES que el sniffer.\n");
        return 1;
    }

    pcap_loop(handle_global, -1, on_packet, (u_char *)&table);

    printf("\n--- Estadísticas Finales ---\n");
    flow_table_expire_all(&table);
    pcap_close(handle_global);

    return 0;
}