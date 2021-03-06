#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>    /* for NF_ACCEPT */
#include <errno.h>
#include <signal.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <string.h>

const char Mal_Site_Table[100][64];
const char *pwd = "/home/rios/bob5/mal_site/mal_site/mal_site.txt";
void sig_int(int signo){
    printf("program exit\n");
    system("iptables -D OUTPUT -p ip -j NFQUEUE --queue-num 0");
    exit(1);
}

/* returns packet id */
static u_int32_t getid (struct nfq_data *tb){
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph)
        id = ntohl(ph->packet_id);
    return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data){
    char HTTP1_1[] = {0x47, 0x45, 0x54, 0x20, 0x2f, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x0d, 0x0a};
    char Host_srt[] = {0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20};
    u_int32_t id = getid(nfa);
    u_char *cp = nfmsg;
    struct ip *iph;
    struct tcphdr *tcph;
    cp += 28;

    iph = (struct ip*)cp;
    cp += sizeof(*iph);
    tcph = (struct tcphdr*)cp;
    cp += sizeof(*tcph);

    if(!memcmp(cp, HTTP1_1, sizeof(HTTP1_1))){
        cp += sizeof(HTTP1_1);
        if(!memcmp(cp, Host_srt, sizeof(Host_srt))){
            cp += sizeof(Host_srt);
            char host[64];
            int i;
            for(i=0; *cp != '\r';i++){
                host[i] = *cp++;
            }
            host[i] = '\0';
            for(i=0; Mal_Site_Table[i][0]; i++){
                if(!strstr(host, Mal_Site_Table[i])){
                    printf("%s Dropped\n", host);
                    return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
                }
            }
        }
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));
    struct sigaction intsig;
    FILE *fp;

    if((fp = fopen(pwd, "r")) == NULL){
        printf("fopen(r) errer\n");
        return 0;
    }

    memset(Mal_Site_Table, 0, 6400);
    for(int i=0; !feof(fp); i++){
        fscanf(fp, "%s", Mal_Site_Table[i]);
    }

    intsig.sa_handler = sig_int;
    sigemptyset(&intsig.sa_mask);
    intsig.sa_flags = 0;

    if (sigaction(SIGINT, &intsig, 0) == -1) {
        printf ("signal(SIGINT) error");
        return -1;
    }
    system("iptables -A OUTPUT -p ip -j NFQUEUE --queue-num 0");
    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
     * are sent from kernel-space, the socket buffer that we use
     * to enqueue packets may fill up returning ENOBUFS. Depending
     * on your application, this error may be ignored. Please, see
     * the doxygen documentation of this library on how to improve
     * this situation.
     */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
   * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}
