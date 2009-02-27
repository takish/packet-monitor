/*
 * $Date: 2004/11/05 04:16:52 $ 
 * $Id: pkt_monitor.c,v 1.5 2004/11/05 04:16:52 takashi Exp $
 * $Revision: 1.5 $
 */

#include <netinet/in.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <sys/time.h>
#include <signal.h>
#include <time.h>
#include <sys/resource.h>

#include <unistd.h>
#include <linux/if_ether.h>
#include <linux/types.h>

#include <linux/filter.h>

#define TIMEOUT_SEC 1
#define TIMEOUT_USEC 0
#define INTVAL 10
#define BUFFER_SIZE 2000

#define ENABLE_BPF
#define OUTPUT

typedef struct {
    int all;
    int ip;
    int ipv6;
    int arp;
    int icmp;
    int tcp;
    int udp;
    int bps;
} packet_counter_t;

struct itimerval timer;

packet_counter_t pkt_cnt;

int
Rand(double lossrate) /* Rand function */
{
    static unsigned int seq = 0;
    static int count = 0;
    long int   base;

    ++seq;

    if (count > 0) {
        count--;
#ifdef VERBOSE
        printf("loss: seq %d\n", seq);
#endif
        return 0;
    }

//    base = ((double)random()) * 100 / RAND_MAX / loss_no_continuous;
    base = ((double)random()) * 100 / RAND_MAX;

    if(lossrate < base){
        return 1;
    } else {
#ifdef VERBOSE
        printf("loss: seq %d\n", seq);
#endif
        return 0;
    }
}

int
raw_udpip_init()
{
    int sockfd;
    int on = 1;

//    if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
    if ((sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
        perror("socket");
        exit(1);
    }

    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("setsockopt");
        exit(1);
    }
    return sockfd;
}

int getifhexaddr(char *interface){
    struct ifreq ifr;
    struct sockaddr_in *sin;
    int sock;
    int addr;

    sock = socket(PF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, interface);
    ioctl(sock, SIOCGIFADDR, &ifr);
    sin = (struct sockaddr_in *)&ifr.ifr_addr;

    return ntohl(sin->sin_addr.s_addr);
}

/* 
 * Receiving  packet 
 */
void recv_pkt(int rsock)
{
  int rsin_size, count;
  struct sockaddr_in rsin;
  struct in_addr insaddr,indaddr;
  fd_set fds;
  int ssock;
  u_char buffer[BUFFER_SIZE];
  int   recvsize;
  struct ethhdr *eth;
  struct iphdr *iph;
  struct ip6hdr *ipv6h;
  struct udphdr *udph;
  struct tcphdr *tcph;


  rsin_size = sizeof(rsin);

  ssock = raw_udpip_init();

  FD_ZERO(&fds);
  FD_SET(rsock, &fds);

  for (;;){
    if( select(rsock + 1, &fds , NULL, NULL, NULL) < 0 ){
//      perror("select");
//      exit(0);
    }

    if ( FD_ISSET(rsock, &fds)){
//      if(recvfrom(rsock, &buf, sizeof(buf), 0, (struct sockaddr *)&rsin, &rsin_size) < 0 ) {
      if((recvsize = recvfrom(rsock, &buffer, sizeof(buffer), 0, (struct sockaddr *)&rsin, &rsin_size)) < 0 ) {
	perror("recvfrom");
      }
      pkt_cnt.all++;
//      printf("%d\n",recvsize);
      pkt_cnt.bps += recvsize;

//	printf("size %d\n", recvsize);

      eth = (struct ethhdr *)buffer;
/*
      if ( buf.ip.protocol != IPPROTO_UDP)
	continue; 
    */
//      printf("%x\n", ntohs(buf.eth.h_proto));
      if ( ntohs(eth->h_proto) == ETH_P_IP)
      {
          pkt_cnt.ip++;
      }
      else if ( ntohs(eth->h_proto) == ETH_P_IPV6)
      {
          pkt_cnt.ipv6++;
          continue;
      }
      else if ( ntohs(eth->h_proto) == ETH_P_ARP)
      {
          pkt_cnt.arp++;
          continue;
      } else {
          continue;
      }

      iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
      if ( iph->protocol == IPPROTO_ICMP)
      {
          pkt_cnt.icmp++;
      }
      if ( iph->protocol == IPPROTO_UDP)
      {
          pkt_cnt.udp++;
      }

      if ( iph->protocol == IPPROTO_TCP)
      {
          pkt_cnt.tcp++;
      }
/*    if(Rand(1)){
printf("%d %s\n",sizeof(buf), &rsin.sin_addr.s_addr);
      if(sendto(ssock, &buf, sizeof(buf), 0, (struct sockaddr_in *)&rsin, sizeof(rsin)) < 0 ) {
	perror("sendto");
      }
    }
*/

    }
  }
}

void setting_priority(void){
    int prio;

    if(geteuid() != 0){
        fprintf(stderr,"#\n# This program requires superuser privilege.\n# You must have \"root\" privilege to execute this program.\n#\n");
        exit(0);
    }

    setpriority(PRIO_PROCESS, 0, -20);
    prio = getpriority(PRIO_PROCESS, 0);
    printf("#  priority %d\n",prio);
}

/* 時間取得関数 */
void get_time(char *timep, int flags){
    time_t  t;

    time(&t);
    strcpy(timep, ctime(&t));

    if(flags){
        /* 時間だけ抽出 */
        timep[strlen(ctime(&t)) - 6] = '\0';
        strcpy(timep, timep + 11);
    } else {
        /* \nの除去 */
        timep[strlen(ctime(&t)) - 1] = '\0';
    }
}

void int_proc(int sig){
    char timep[30];
    static int sec = 1;

    get_time(timep, 1);

    if((sec % INTVAL) == 1){
        printf("# time #\t  all\t ipv4\t ipv6\tarp\ticmp\ttcp\tudp\n");
        sec = 1;
    }

    printf("%s\t%5d\t%5d\t%5d\t%3d\t%3d\t%5d\t%5d%6.1fkbps\n",
       timep, pkt_cnt.all, pkt_cnt.ip, 
       pkt_cnt.ipv6, pkt_cnt.arp, pkt_cnt.icmp, 
       pkt_cnt.tcp, pkt_cnt.udp, (double)pkt_cnt.bps*8/1024);

    sec++;

    memset(&pkt_cnt, 0, sizeof(pkt_cnt));
}

void setting_timer(void){
    signal(SIGALRM, int_proc);
    timer.it_interval.tv_sec = TIMEOUT_SEC;
    timer.it_interval.tv_usec = TIMEOUT_USEC;
    timer.it_value.tv_sec = TIMEOUT_SEC;
    timer.it_value.tv_usec = TIMEOUT_USEC;
    setitimer(ITIMER_REAL, &timer, NULL);
}

int
main(int argc, char *argv[]) {

  struct ifreq ifr;
  struct packet_mreq mreq;        
  int rsock;


#ifdef ENABLE_BPF
  /*
   * tcpdump -dd -s 1600 src host not 165.242.42.206
   * INPUT
   */
  struct sock_filter BPF_code[] = {
      { 0x28, 0, 0, 0x0000000c },
      { 0x15, 0, 2, 0x00000800 },
      { 0x20, 0, 0, 0x0000001a },
//      { 0x15, 4, 5, 0xa5f22acd },
      { 0x15, 4, 5, getifhexaddr(argv[1])},
      { 0x15, 1, 0, 0x00000806 },
      { 0x15, 0, 3, 0x00008035 },
      { 0x20, 0, 0, 0x0000001c },
//      { 0x15, 0, 1, 0xa5f22acd },
      { 0x15, 0, 1, getifhexaddr(argv[1]) },
//      { 0x6, 0, 0, 0x00000060 }
      { 0x6, 0, 0, 0x00000000 },
      { 0x6, 0, 0, 0x00000640 }// -s により1600byteのデータを取得
  };
  /*
   * tcpdump -dd -s 1600 src host 165.242.42.206
   * OUTPUT
   */
  struct sock_filter BPF_codeOUT[] = {
      { 0x28, 0, 0, 0x0000000c },
      { 0x15, 0, 2, 0x00000800 },
      { 0x20, 0, 0, 0x0000001a },
//      { 0x15, 4, 5, 0xa5f22acd },
      { 0x15, 4, 5, getifhexaddr(argv[1])},
      { 0x15, 1, 0, 0x00000806 },
      { 0x15, 0, 3, 0x00008035 },
      { 0x20, 0, 0, 0x0000001c },
//      { 0x15, 0, 1, 0xa5f22acd },
      { 0x15, 0, 1, getifhexaddr(argv[1]) },
//      { 0x6, 0, 0, 0x00000060 }
      { 0x6, 0, 0, 0x00000640 },// -s により1600byteのデータを取得
      { 0x6, 0, 0, 0x00000000 }
  };

  struct sock_filter BPF_bicode[] = {
      { 0x6, 0, 0, 0x00000060 }
  };

  struct sock_filter BPF_debug[] = {
    { 0x28, 0, 0, 0x0000000c },
    { 0x15, 0, 2, 0x00000800 },
    { 0x20, 0, 0, 0x0000001a },
    { 0x15, 4, 5, 0xc0a80114 },
    { 0x15, 1, 0, 0x00000806 },
    { 0x15, 0, 3, 0x00008035 },
    { 0x20, 0, 0, 0x0000001c },
    { 0x15, 0, 1, 0xc0a80114 },
    { 0x6, 0, 0, 0x00000060 },
    { 0x6, 0, 0, 0x00000000 }
  };
  struct sock_fprog Filter;

  Filter.len = 10;
  Filter.filter = BPF_code;
#endif
  
  if(argc != 2) {
    printf("Usage: %s interface\n", argv[0]);
    exit(1);
  }


#ifdef OUTPUT 
        Filter.filter = BPF_codeOUT;
#endif

  setting_priority();
  setting_timer();

//  if ((rsock = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) < 0 ){
  if ((rsock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0 ){
    perror("socket");
    exit(0);
  }

  strcpy(ifr.ifr_name, argv[1]);

  if(ioctl(rsock, SIOCGIFINDEX, &ifr) < 0 ){            
    perror("ioctl SIOCGIFINDEX");
    exit(0);
  }

  mreq.mr_type = PACKET_MR_PROMISC;
  mreq.mr_ifindex = ifr.ifr_ifindex;
  mreq.mr_alen = 0;
  mreq.mr_address[0] ='\0';

  if( (setsockopt(rsock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, (void *)&mreq, sizeof(mreq))) < 0){
    perror("setsockopt");
    exit(0);
  }
        
#ifdef ENABLE_BPF
      /* Attach the filter to the socket */
    if( setsockopt(rsock, SOL_SOCKET, SO_ATTACH_FILTER, &Filter, sizeof(Filter)) < 0 ) {
//    if( setsockopt(rsock, SOL_SOCKET, SO_DETACH_FILTER, &Filter, sizeof(Filter)) < 0 ) {
        perror("setsockopt");
        close(rsock);
        exit(EXIT_FAILURE);
    }
#endif

  recv_pkt(rsock);

  return 0;
}
