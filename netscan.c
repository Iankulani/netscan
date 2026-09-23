#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>

#define PACKET_SIZE 64
#define MAX_HOSTS   256
#define TIMEOUT_SEC 2

/* ICMP packet structure */
struct icmp_packet {
    struct icmphdr hdr;
    char payload[PACKET_SIZE - sizeof(struct icmphdr)];
};

/* Result storage */
struct scan_result {
    char ip[INET_ADDRSTRLEN];
    int  alive;
    double rtt_ms;
};

static struct scan_result results[MAX_HOSTS];
static int result_count = 0;
static pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ---------- Checksum ---------- */
static unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

/* ---------- Safe IP-string copy helper (always null-terminated) ---------- */
static void copy_ip(char *dst, const char *src) {
    size_t len = strlen(src);
    if (len >= INET_ADDRSTRLEN)
        len = INET_ADDRSTRLEN - 1;
    memcpy(dst, src, len);
    dst[len] = '\0';
}

/* ---------- Ping a single IP ---------- */
static int ping_host(const char *ip, double *rtt_out) {
    int sockfd;
    struct sockaddr_in addr;
    struct icmp_packet packet;
    struct timeval tv_out, tv_in;
    char recvbuf[1024];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket (need root)");
        return -1;
    }

    /* Set receive timeout */
    tv_out.tv_sec  = TIMEOUT_SEC;
    tv_out.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv_out, sizeof(tv_out));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip);

    /* Build ICMP echo request */
    memset(&packet, 0, sizeof(packet));
    packet.hdr.type = ICMP_ECHO;
    packet.hdr.code = 0;
    packet.hdr.un.echo.id = htons(getpid() & 0xFFFF);
    packet.hdr.un.echo.sequence = htons(1);
    memset(packet.payload, 'A', sizeof(packet.payload));
    packet.hdr.checksum = checksum(&packet, sizeof(packet));

    gettimeofday(&tv_in, NULL);

    if (sendto(sockfd, &packet, sizeof(packet), 0,
               (struct sockaddr *)&addr, sizeof(addr)) <= 0) {
        close(sockfd);
        return 0;
    }

    /* Wait for reply */
    while (1) {
        int n = recvfrom(sockfd, recvbuf, sizeof(recvbuf), 0,
                         (struct sockaddr *)&from, &fromlen);
        if (n < 0) {
            close(sockfd);
            return 0; /* timeout */
        }

        struct iphdr *iph = (struct iphdr *)recvbuf;
        struct icmphdr *icmph = (struct icmphdr *)(recvbuf + (iph->ihl * 4));

        if (icmph->type == ICMP_ECHOREPLY &&
            icmph->un.echo.id == htons(getpid() & 0xFFFF)) {

            struct timeval tv_now;
            gettimeofday(&tv_now, NULL);

            double elapsed = (tv_now.tv_sec - tv_in.tv_sec) * 1000.0 +
                             (tv_now.tv_usec - tv_in.tv_usec) / 1000.0;
            *rtt_out = elapsed;
            close(sockfd);
            return 1;
        }
    }
}

/* ---------- Thread worker ---------- */
struct thread_arg {
    char ip[INET_ADDRSTRLEN];
};

static void *scan_worker(void *arg) {
    struct thread_arg *ta = (struct thread_arg *)arg;
    double rtt = 0.0;

    int alive = ping_host(ta->ip, &rtt);

    pthread_mutex_lock(&result_mutex);
    if (result_count < MAX_HOSTS) {
        copy_ip(results[result_count].ip, ta->ip);
        results[result_count].alive  = alive;
        results[result_count].rtt_ms = alive ? rtt : 0.0;
        result_count++;
    }
    pthread_mutex_unlock(&result_mutex);

    free(ta);
    return NULL;
}

/* ---------- Packet monitor (sniffer) ---------- */
static void *packet_monitor(void *arg) {
    (void)arg;
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        perror("monitor socket");
        return NULL;
    }

    printf("[MONITOR] Packet monitor started (capturing ICMP packets)\n");

    unsigned char buf[65536];
    while (1) {
        int n = recv(sock, buf, sizeof(buf), 0);
        if (n <= 0) continue;

        struct iphdr *iph = (struct iphdr *)buf;
        struct sockaddr_in src, dst;
        src.sin_addr.s_addr = iph->saddr;
        dst.sin_addr.s_addr = iph->daddr;

        if (iph->protocol == IPPROTO_ICMP) {
            struct icmphdr *icmph = (struct icmphdr *)(buf + (iph->ihl * 4));
            const char *type_str =
                (icmph->type == ICMP_ECHO)         ? "ECHO-REQUEST"  :
                (icmph->type == ICMP_ECHOREPLY)    ? "ECHO-REPLY"    :
                (icmph->type == ICMP_DEST_UNREACH) ? "DEST-UNREACH"  : "OTHER";

            printf("[MONITOR] %s -> %s  ICMP %s  len=%d\n",
                   inet_ntoa(src.sin_addr),
                   inet_ntoa(dst.sin_addr),
                   type_str, n);
        }
    }
    close(sock);
    return NULL;
}

/* ---------- Usage ---------- */
static void usage(const char *prog) {
    printf("Usage:\n");
    printf("  %s <ip>                  Scan a single IP\n", prog);
    printf("  %s <start_ip> <end_ip>   Scan an IP range\n", prog);
    printf("  %s <subnet>/<cidr>       Scan a subnet (e.g. 192.168.1.0/24)\n", prog);
    printf("\nExample:\n  sudo %s 192.168.1.1\n  sudo %s 192.168.1.0/24\n",
           prog, prog);
}

/* ---------- Parse subnet ---------- */
static int expand_cidr(const char *cidr, char ips[][INET_ADDRSTRLEN], int max) {
    char base[INET_ADDRSTRLEN];
    int prefix;
    if (sscanf(cidr, "%15[^/]/%d", base, &prefix) != 2) return 0;
    if (prefix < 16 || prefix > 32) {
        fprintf(stderr, "Prefix must be /16 to /32\n");
        return 0;
    }

    struct in_addr addr;
    if (inet_aton(base, &addr) == 0) return 0;

    unsigned int mask  = (prefix == 32) ? 0xFFFFFFFFu
                                        : (0xFFFFFFFFu << (32 - prefix));
    unsigned int net   = ntohl(addr.s_addr) & mask;
    unsigned int bcast = net | ~mask;

    int count = 0;
    for (unsigned int i = net + 1; i < bcast && count < max; i++) {
        struct in_addr a;
        a.s_addr = htonl(i);
        copy_ip(ips[count], inet_ntoa(a));
        count++;
    }
    return count;
}

/* ---------- Main ---------- */
int main(int argc, char *argv[]) {
    if (argc < 2 || argc > 3) {
        usage(argv[0]);
        return 1;
    }

    if (geteuid() != 0) {
        fprintf(stderr,
                "Error: this tool requires root privileges.\n"
                "Run with: sudo %s ...\n", argv[0]);
        return 1;
    }

    char targets[MAX_HOSTS][INET_ADDRSTRLEN];
    int n_targets = 0;

    /* Determine target list */
    if (strchr(argv[1], '/')) {
        n_targets = expand_cidr(argv[1], targets, MAX_HOSTS);
        if (n_targets == 0) {
            fprintf(stderr, "Invalid CIDR\n");
            return 1;
        }
    } else if (argc == 3) {
        struct in_addr a1, a2;
        if (!inet_aton(argv[1], &a1) || !inet_aton(argv[2], &a2)) {
            fprintf(stderr, "Invalid IP(s)\n");
            return 1;
        }
        unsigned int s = ntohl(a1.s_addr), e = ntohl(a2.s_addr);
        if (s > e) {
            fprintf(stderr, "Start > End\n");
            return 1;
        }
        for (unsigned int i = s; i <= e && n_targets < MAX_HOSTS; i++) {
            struct in_addr a;
            a.s_addr = htonl(i);
            copy_ip(targets[n_targets++], inet_ntoa(a));
        }
    } else {
        struct in_addr tmp;
        if (!inet_aton(argv[1], &tmp)) {
            fprintf(stderr, "Invalid IP\n");
            return 1;
        }
        copy_ip(targets[0], argv[1]);
        n_targets = 1;
    }

    printf("=====================================================\n");
    printf(" Network Scanner starting...\n");
    printf(" Targets: %d\n", n_targets);
    printf("=====================================================\n\n");

    /* Start monitor thread (daemon-like) */
    pthread_t monitor_tid;
    pthread_create(&monitor_tid, NULL, packet_monitor, NULL);
    pthread_detach(monitor_tid);

    sleep(1);

    /* Launch scan threads */
    pthread_t threads[MAX_HOSTS];
    int       started = 0;

    for (int i = 0; i < n_targets; i++) {
        struct thread_arg *ta = malloc(sizeof(*ta));
        if (!ta) continue;

        /* Both buffers are char[INET_ADDRSTRLEN] — full copy is safe */
        memcpy(ta->ip, targets[i], sizeof(ta->ip));

        if (pthread_create(&threads[started], NULL, scan_worker, ta) != 0) {
            perror("pthread_create");
            free(ta);
        } else {
            started++;
        }
    }

    for (int i = 0; i < started; i++)
        pthread_join(threads[i], NULL);

    /* Give the monitor a moment, then print results */
    sleep(1);

    printf("\n================== SCAN RESULTS ==================\n");
    int alive_count = 0;
    for (int i = 0; i < result_count; i++) {
        if (results[i].alive) {
            printf("  [+] %-16s ALIVE   (%.2f ms)\n",
                   results[i].ip, results[i].rtt_ms);
            alive_count++;
        } else {
            printf("  [-] %-16s no response\n", results[i].ip);
        }
    }
    printf("==================================================\n");
    printf(" Hosts alive: %d / %d\n", alive_count, n_targets);
    printf("==================================================\n");

    return 0;
}
