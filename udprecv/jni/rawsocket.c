// nlasp.c

/* this file is just used to test communication with the kernel module */
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <arpa/inet.h>   
#include <netdb.h>
#include <net/if.h>

#define TRACE_ENTRY printf("Entering %s\n", __func__)
#define TRACE_EXIT  printf("Exiting %s\n", __func__)


struct sch_config {
	unsigned char protocol;
	unsigned int  pkt_num;
	unsigned int  delay;
	struct sockaddr_in saddr;
	struct sockaddr_in daddr;
	char eth_name[16];
	int socket;
	int is_running;
};

typedef struct _opt_tcp
{
	uint8_t opt_code;
	uint8_t opt_len;
} opt_tcp;


static struct sch_config sf;
unsigned char *data_to_user;
//static FILE *rx_log_file = NULL;
//static FILE *tx_log_file = NULL;

unsigned short sport = 4000;

unsigned int pkts = 0, bytes = 0;

unsigned char protocol = IPPROTO_UDP;

struct timeval tv_start, tv_end;

char *tt_inet_ntoa(const unsigned int addr, char *buf)
{
	u_char s1 = (addr & 0xFF000000) >> 24;
	u_char s2 = (addr & 0x00FF0000) >> 16;
	u_char s3 = (addr & 0x0000FF00) >> 8;
	u_char s4 = (addr & 0x000000FF);
	sprintf(buf, "%d.%d.%d.%d", s4, s3, s2, s1);
	return buf;
}



uint16_t csum(u_char *addr, int count)
{
	/* Compute Internet Checksum for "count" bytes
	 *         beginning at location "addr".
	 */
	register long sum = 0;

	while(count > 1)  {
		/*  This is the inner loop */
		sum += * ((unsigned short *) addr);
		addr += 2;
		count -= 2;
	}

	/*  Add left-over byte, if any */
	if(count > 0)
		sum += * (unsigned char *) addr;

	/*  Fold 32-bit sum to 16 bits */
	while(sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}

struct psd_header {
	unsigned long saddr; // sip
	unsigned long daddr; // dip
	u_char mbz;// 0
	u_char ptcl; // protocol
	unsigned short tcpl; //TCP lenth

};

uint16_t tcp_csum(uint32_t saddr, uint32_t daddr, u_char *tcppkt, uint16_t len)
{
	u_char buf[1600], *pkt;
	uint16_t rst;
	struct psd_header *psdh;
	int count = sizeof(struct psd_header) + len;
	memset(buf, 0, count);
	//  TRACE_ENTRY;
	psdh = (struct psd_header *) buf;
	pkt = buf + sizeof(struct psd_header);
	psdh->saddr = saddr;
	psdh->daddr = daddr;
	psdh->mbz = 0;
	psdh->ptcl = IPPROTO_TCP;
	psdh->tcpl = htons(len);
	memcpy(pkt, tcppkt, len);
	rst = csum(buf, count);
	// TRACE_EXIT;
	return rst;
}

unsigned char pkt_buf[10240];


unsigned char ether_dhost[ETH_ALEN] = {0xb8, 0xca, 0x3a, 0xbb, 0xfa, 0x81};
unsigned char ether_shost[ETH_ALEN] = {0xb8, 0xca, 0x3a, 0xbb, 0xfa, 0x82};

double get_current_ts()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0;
}
// initialize a start ack number through generating a random number  
	unsigned int 
init_ackseq()
{
	srand((unsigned int)time(NULL));
	return rand();
}
// // 

////////////////////////////////raw socket for tx //////////////////////////////////////////////////////////////////
	int
syn_packets_tx()
{
	int pktlen = sizeof(struct iphdr) + sizeof(struct tcphdr) + 20;
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	opt_tcp *opt;
	struct timeval now;


	unsigned char *option = NULL;
	unsigned int seq = 0;
	int res = 0, i = 0;
	char buf1[32], buf2[32];
	unsigned long duration;
	unsigned int *tv_tx;
	now.tv_sec = 0;
	now.tv_usec = 0;

	if(!pkt_buf)
	{
		printf("malloc ip packet buff (%d) failure\n", pktlen);
		return;//now;
	}
	memset(pkt_buf, 0, pktlen);

	iph = (struct iphdr *)pkt_buf;
	tcph = (struct tcphdr *)(pkt_buf + sizeof(struct iphdr));
	option = (unsigned char *)(pkt_buf + sizeof(struct iphdr) + sizeof(struct tcphdr));


	iph->version = 4;
	iph->ihl = sizeof(struct iphdr) >> 2;
	iph->frag_off = 0;
	iph->protocol = IPPROTO_TCP;
	iph->tos = 0;
	iph->daddr = sf.daddr.sin_addr.s_addr; // inet_addr("158.132.255.23");
	iph->saddr = sf.saddr.sin_addr.s_addr; // inet_addr("158.132.255.62");
	iph->ttl = 0x40;
	iph->id = htons(777);
	iph->tot_len = htons(pktlen);
	iph->check = 0;



	tcph->source = sf.saddr.sin_port;
	tcph->dest = sf.daddr.sin_port;


	tcph->doff = (sizeof(struct tcphdr) + 20)>>2;
	tcph->psh = 0;
	tcph->fin = 0;
	tcph->syn = 1;
	tcph->ack = 0;
	tcph->check = 0;
	tcph->window = htons(5840);


	seq = init_ackseq();

	tcph->ack_seq = htonl(0);

	opt = (opt_tcp *)option;
	opt->opt_code = 0x02;
	opt->opt_len = 0x04;
	*((unsigned short *)(option + 2)) = htons(1460);
	option += opt->opt_len;

	opt = (opt_tcp *)option;
	opt->opt_code = 0x04;
	opt->opt_len = 0x02;
	option += opt->opt_len;

	opt = (opt_tcp *)option;
	opt->opt_code = 0x08;
	opt->opt_len = 0x0a;
	tv_tx = (unsigned int *)(option+2);
	option += opt->opt_len;

	*option = 0x01;
	option += 1;

	opt = (opt_tcp *)option;
	opt->opt_code = 0x03;
	opt->opt_len = 0x03;
	*(option+2) = 0x04;
	option += opt->opt_len;

	tcph->source = sf.saddr.sin_port + 1;
	tcph->seq = htonl(seq);
	seq += 23223;
	gettimeofday(&now, NULL);
	*tv_tx = ntohl(now.tv_sec<<20+now.tv_usec);

	iph->check = csum((void *)iph, iph->ihl * 4);
	//printf("checksum: %x\n", iph->check);
	tcph->check = tcp_csum(iph->saddr, iph->daddr, (u_char *)tcph, sizeof(struct tcphdr)+20);

	return sendto(sf.socket, pkt_buf, pktlen, 0, (struct sockaddr*)&sf.daddr, sizeof(sf.daddr));
}

int pkt_construct(int pkt_len, unsigned int seq, unsigned int ack, unsigned char protocol)
{
	int pktlen = 0;
	if(protocol == IPPROTO_UDP)
		pktlen = pkt_len + sizeof(struct iphdr) + sizeof(struct udphdr);
	else
		pktlen = pkt_len + sizeof(struct iphdr) + sizeof(struct tcphdr);

	unsigned char *ip_buf = NULL;//kmalloc(pktlen, GFP_KERNEL);
	//   struct ether_header *ethh = NULL;
	struct iphdr *iph = NULL;//(struct iphdr *)ip_buf;
	struct tcphdr *tcph = NULL;//(struct tcphdr *)(ip_buf + sizeof(struct iphdr));
	struct udphdr *udph = NULL;
	char *data = NULL, buf1[16], buf2[16];//ip_buf + sizeof(struct iphdr) + sizeof(struct tcphdr);
	//  struct timeval now;
	int res = 0;
	double tx_ts = 0.0;

	// if(pktlen < sizeof(struct timeval))
	//    pktlen = sizeof(struct timeval);

	ip_buf = pkt_buf;
	/*  ethh = (struct ether_header *)ip_buf;
			memcpy(ethh->ether_shost, ether_shost, ETH_ALEN);
			memcpy(ethh->ether_dhost, ether_dhost, ETH_ALEN);
			ethh->ether_type = htons(ETHERTYPE_IP);
			ip_buf += sizeof(struct ether_header);*/
	iph = (struct iphdr *) ip_buf;

	memset(ip_buf, 0, pktlen);
	iph->ihl = sizeof(struct iphdr) >> 2;
	iph->frag_off = 0;
	iph->protocol = protocol;
	iph->tos = 0;
	iph->daddr = sf.daddr.sin_addr.s_addr; // inet_addr("158.132.255.23");
	iph->saddr = sf.saddr.sin_addr.s_addr; // inet_addr("158.132.255.62");
	//printf("%s  --> %s\n",  tt_inet_ntoa(iph->saddr, buf1), tt_inet_ntoa(iph->daddr, buf2));
	iph->ttl = 0x40;

	iph->tot_len = htons(pktlen);
	iph->check = 0;
	iph->id = seq++;
	iph->check = csum((void *) iph, iph->ihl * 4);

	tx_ts = get_current_ts();

	switch(protocol) {
		case IPPROTO_TCP:
			tcph = (struct tcphdr*)(ip_buf + sizeof(struct iphdr));
			tcph->source = sf.saddr.sin_port;//htons ( sport );
			tcph->dest = sf.daddr.sin_port;// htons ( 8081 );
			tcph->ack_seq = 0x00000000;
			tcph->doff = 5;
			tcph->psh = 0;
			tcph->fin = 0;
			tcph->syn = 1;
			tcph->ack = 0;
			tcph->check = 0;
			tcph->window = htons(5840);
			tcph->seq = htonl(3333);
			data = ip_buf + sizeof(struct iphdr) + sizeof(struct tcphdr);
			*((double *)data) = tx_ts;
			tcph->check = tcp_csum(iph->saddr, iph->daddr, (u_char *) tcph, pkt_len + sizeof(struct tcphdr));
			break;
		case IPPROTO_UDP:
			udph = (struct udphdr *)(ip_buf + sizeof(struct iphdr));
			udph->source = sf.saddr.sin_port;
			udph->dest   = sf.daddr.sin_port;
			udph->len    = htons(pkt_len + sizeof(struct udphdr));
			data = ip_buf + sizeof(struct iphdr) + sizeof(struct udphdr);
			*((double *)data) = tx_ts;
			udph->check  = tcp_csum(iph->saddr, iph->daddr, (u_char *) udph, pkt_len + sizeof(struct udphdr));
			break;
		default:
			printf("Unknown transmition layer.\n");
			return 0;
			break;
	}

	return pktlen;
}


int pkt_schedule1(int pktlen, unsigned int delay, unsigned char protocol)
{
	if(delay > 0)
		usleep(delay);

	static unsigned int seq = 0001;
	static unsigned int ack = 0002;
	int res = sendto(sf.socket, pkt_buf, pktlen, 0, (struct sockaddr*)&sf.daddr,
			sizeof(sf.daddr));
	return res;
}

int pkt_schedule(int dlen, unsigned int delay, unsigned char protocol)
{
	if(delay > 0)
		usleep(delay);

	static unsigned int seq = 0001;
	static unsigned int ack = 0002;
	int pktlen = pkt_construct(dlen, seq, ack, protocol);
	int res = sendto(sf.socket, pkt_buf, pktlen, 0, (struct sockaddr*)&sf.daddr,
			sizeof(sf.daddr));
	seq += dlen;
	return res;
}


int pkts_tx(int num, int len, int delay)
{
	struct timeval ts;
	double t;
	if(num <= 0 || len < 0)
		return 0;

	int i = 0;
	double tx_s, tx_e;

	tx_s = get_current_ts();

	int pktlen = pkt_construct(len, 1, 2, protocol);
	for(i = 0; i < num; i++) {
		tx_e = get_current_ts();
		if (pkt_schedule1(pktlen,  delay, protocol) < 0)
		{
			printf("Send packet error.\n");
		}
		//printf("%f..tx\n", tx_e);
	}

	tx_e = get_current_ts();

	printf("Scheduled %d %d bytes packets between %f and %f.\n", num, len, tx_s, tx_e);
}

void syn_ping(int delay)
{
	int i;
	int res;
	char buf[16];
	int d, retval, len, r;
	/* fd_set set;
		 struct timeval timeo = {1, 0};

		 struct sockaddr_in addr;
		 struct ether_header *peth;
		 struct iphdr *iph;
		 struct tcphdr *tcph;
		 struct udphdr *udph;
		 unsigned char *tmp;*/

	system("rm -rf /sdcard/rillog.txt");

	if(sf.daddr.sin_addr.s_addr == 0 || sf.daddr.sin_port == 0 || sf.pkt_num == 0)
		return 0;

	sf.daddr.sin_family = AF_INET;
	printf("%s:%d  num=%d  delay=%d us\n", tt_inet_ntoa(sf.daddr.sin_addr.s_addr, buf), ntohs(sf.daddr.sin_port), sf.pkt_num, sf.delay);

	if((sf.socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror("Create raw socket error.\n");
		return 0;
	}


	//do_promisc(sf.eth_name, sf.socket);
	//sf.saddr.sin_addr.s_addr = inet_addr("158.132.10.197");
	sf.saddr.sin_port = htons(25001);
	printf("Ping: num=%d, delay=%d\n", sf.pkt_num, sf.delay);
	protocol = IPPROTO_TCP;
	/* if (bind(sf.socket, (struct sockaddr *)&sf.saddr, sizeof(sf.saddr))<0){  
		 perror("connect");  
		 exit(1);  
		 } */ 
	for(i = 0; i < sf.pkt_num; i ++) {
		res = syn_packets_tx();

		if(res < 0)
			printf("%d send syn packet error(%d) \n", i, res);
		d = delay + (i * 10000);
		printf("delay %d us\n", d);
		usleep(d);

	}

	close(sf.socket);
	system("mv /sdcard/rillog.txt /sdcard/rilping.txt");
}

void tx_test()
{
	int i = 0;
	int j = 10;
	for(i = 0; i*j < 1450; i++)
	{
		pkts_tx(sf.pkt_num, i*j, sf.delay);
		sleep(1);
	}
}

void raw_tx_test()
{
	char buf1[16], buf2[16];
	printf("Enter udp raw socket test founcion.\n");
	if(sf.daddr.sin_addr.s_addr == 0 || sf.daddr.sin_port == 0 || sf.pkt_num == 0)
		return 0;

	// sf.saddr.sin_addr.s_addr = inet_addr("158.132.10.197");
	sf.saddr.sin_port = htons(25001);
	sf.daddr.sin_family = AF_INET;
	printf("%s:%d-%s:%d  num=%d  delay=%d us\n", tt_inet_ntoa(sf.saddr.sin_addr.s_addr, buf1), ntohs(sf.saddr.sin_port),
			tt_inet_ntoa(sf.daddr.sin_addr.s_addr, buf2), ntohs(sf.daddr.sin_port), sf.pkt_num, sf.delay);

	if((sf.socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror("Create raw socket error.\n");
		return 0;
	}

	tx_test();
	close(sf.socket);
}




////////////////////////////////raw socket for rx ///////////////////////////////////////////////////////////////
ip_process(char *data, struct timeval tv_rx, int len)
{
	struct iphdr  *iph = NULL;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	struct timeval now;
	char buf1[16], buf2[16];

	iph = (struct iphdr *) data;

	if(len < ntohs(iph->tot_len)) {
		printf("%4x received uncomplete packet(%d %d)\n", iph->id, len, ntohs(iph->tot_len));
		return -1;
	}
	//return -1;
	// log
	gettimeofday(&now, NULL);

	//printf("%d\n", iph->protocol);
	switch(iph->protocol) {
		case IPPROTO_UDP:
			//  printf("UDP packet len = %d\n", len);
			break;http://wangwei007.blog.51cto.com/68019/1100742
				udph = (struct udphdr *)((char *) iph + (iph->ihl << 2));

			if(ntohs(udph->dest) > 10000 && ntohs(udph->dest) < 10010) {
				if(pkts == 0) {
					tv_start = now;
					printf("start: %d.%d\n", now.tv_sec, now.tv_usec);
				}

				pkts++;
				bytes += (len + 14);
				tv_end = now;
				// printf("%d: %d\n", ntohs(iph->id), len);
			}

			break;
		case IPPROTO_TCP:
			//printf("TCP packet len = %d\n", len);
			//   break;
			tcph = (struct tcphdr *)((char *) iph + (iph->ihl << 2));

			if(ntohs(tcph->source) != 80) {
				//rule_del_ker(pinfo, id);
			}

			printf(" %s.%d  --> %s.%d (%d) at %d.%d\n",  tt_inet_ntoa(iph->saddr, buf1),
					ntohs(tcph->source), tt_inet_ntoa(iph->daddr, buf2),
					ntohs(tcph->dest), iph->protocol, tv_rx.tv_sec, tv_rx.tv_usec);

			break;
		case IPPROTO_ICMP:
			printf("ICMP packet len = %d\n", len);
			break;
		default:
			break;
	}

	return 0;
}

int do_promisc(char *nif, int sock)
{
	struct ifreq ifr;

	strncpy(ifr.ifr_name, nif, strlen(nif) + 1);

	if((ioctl(sock, SIOCGIFFLAGS, &ifr) == -1)) { //获得flag
		perror("ioctl error 2");
		exit(2);
	}

	ifr.ifr_flags |= IFF_PROMISC;  //重置flag标志

	if(ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) { //改变模式
		perror("ioctl error 3");
		exit(3);
	}
}

void rx_test()
{
	struct sockaddr_in addr;
	struct ether_header *peth;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;
	unsigned char *tmp;
	int r = 0, len = 0;
	struct timeval rx_tv;
	sf.is_running = 1;

	while(sf.is_running) {
		len = sizeof(addr);
		//printf("packet\n");
		r = recvfrom(sf.socket, pkt_buf, sizeof(pkt_buf), 0, (struct sockaddr *)&addr, &len);
		//printf("packet len = %d\n", r);
		//continue;
		pkt_buf[r] = 0;
		tmp = pkt_buf;
		peth = (struct ether_header *)tmp;
		tmp += sizeof(struct ether_header);
		iph = (struct iphdr *) tmp;
		//tmp += sizeof(struct iphdr);
		len = r - sizeof(struct ether_header);
		gettimeofday(&rx_tv, NULL);
		//continue;
		if(ntohs(peth->ether_type) == ETHERTYPE_IP)
			ip_process(tmp, rx_tv, len);
		// elseif (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr))<0){  
		perror("connect");  
		exit(1);  
	}  
	// printf("eth type: %x\n", ntohs(peth->ether_type));

	}

	void raw_rx_test()
	{
		if(!sf.eth_name) {
			printf("no eth.\n");
			exit(0);
		}

		printf("Listen on: %s\n", sf.eth_name);
		if((sf.socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
			printf("socket error!\n");
			exit(0);
		}

		do_promisc(sf.eth_name, sf.socket);
		rx_test();


		close(sf.socket);
	}

	///////////////////////////////////////// raw socket for rx /////////////////////////////////////////////////


	void pktloss(void)
	{

		int gap = 0;

		pkts_tx(100, 200, gap);
		usleep(1000 * 10);
		pkts_tx(100, 800, gap);
		usleep(1000 * 10);
		pkts_tx(100, 1400, gap);
		usleep(1000 * 10);
		printf("finisth\n");
	}
	void pkt_schedule_test(void)
	{
		int i = 0;
		int timegap = 0;

		int gap = 0;
		// ip_packets_tx(5, 1000, gap);
		//sleep(15);

		for(i = 1; i < 11; i++) {
			pkts_tx(10, 0, gap);
			usleep(timegap * 10 * 2);
		}

		printf("finisth\n");
		return;
	}

	void delaytest(void)
	{
		int i, j;
		int gap = 0;

		for(i = 0; i < 147; i++) {
			for(j = 0; j < 10; j++) {
				pkts_tx(1, i * 10, gap);
				usleep(10000);
			}
		}
	}


	void test(void)
	{
		char test[1024];
		//  struct timeval ti;
		sprintf(test, "data");

		// nl_send_data(pinfo, test, strlen(test)+1, MSG_TEST_DATA);
		printf("send data(%d): %s\n", strlen(test), test);

	}

	void terminate(int signo)
	{
		sf.is_running = 0;
		printf("\nexit\n");
		// print_rx_res();
		exit(0);

	}

#define OPT_RAW_SND 1
#define OPT_RAW_RCV 2
#define OPT_SYN_PING 3
	void print_help(void)
	{
		printf("USAGE:\n");
		printf("Example: ./test -t rsnd -d 192.168.1.1 -p 80 -n 10 -g 0 \n");
		printf("Example: ./test -t rrcv -d 192.168.1.1 -p 25002\n");
		printf("-t operation type (rsnd for tx, rrcv for rx)\n");
		printf("-i device name for rx\n");
		printf("-d dest ip for rx and tx\n");
		printf("-p dest port for rx and tx\n");
		printf("-n packet number for rx\n");
		printf("-g time gab between two packets for tx\n");
		printf("-h print hlep infomation\n");
	}

	// get the ip address of the ethernet device
	unsigned int 
		get_local_ip(char *eth)
		{
			int sock;
			struct ifconf ifconf;
			struct ifreq ifreq[255];
			int interfaces;
			int i;
			unsigned int sip = 0;
			sock = socket(AF_INET, SOCK_STREAM, 0);
			if (sock < 0)
			{
				//printf("%d: Create socket error.\n", __LINE__);
				return 0;
			}
			ifconf.ifc_buf = (char*)ifreq;
			ifconf.ifc_len = sizeof(ifreq);
			if(ioctl(sock, SIOCGIFCONF, &ifconf) == -1)
			{
				close(sock);
				//printf("%d: ioctl error.\n", __LINE__);
				return 0;
			}
			interfaces = ifconf.ifc_len / sizeof(ifreq[0]);
			for (i = 0; i < interfaces; i++)
			{
				char ip[INET_ADDRSTRLEN];
				struct sockaddr_in *address = (struct sockaddr_in *) &ifreq[i].ifr_addr;
				// Convert the binary IP address into a readable string.
				if (!inet_ntop(AF_INET, &address->sin_addr, ip, sizeof(ip)))
				{
					//printf("%d: inet_ntop error ..\n");
					continue;
				}
				if(strcmp(ifreq[i].ifr_name, eth) == 0)
				{
					sip = inet_addr(ip);
					printf("%s\t%s\n", ifreq[i].ifr_name, ip);  
					break;
				}      
			}
			close(sock);
			return sip;  
		}

	int get_conf(int argc, char *argv[])
	{
		int res = 0;
		char opt;
		char buf[16];

		//memset((char *)m_cfg, 0, sizeof(m_cfg));
		while((opt = getopt(argc, argv, "t:i:d:p:n:g:")) != -1) {
			//printf("opt=%b\n", opt);
			switch(opt) {
				case 't':/* work type: tx or rx*/
					strcpy(buf, optarg);
					printf("opt type: %s\n", optarg);
					break;

				case 'i': /* device: for rx */
					strcpy(sf.eth_name, optarg);
					sf.saddr.sin_addr.s_addr = get_local_ip(sf.eth_name);
					break;  /* dest ip: for both rx and tx */

				case 'd':
					sf.daddr.sin_addr.s_addr = inet_addr(optarg);
					break;

				case 'p': /* dest port: for both rx and tx */
					sf.daddr.sin_port = htons(atoi(optarg));
					break;

				case 'n': /* pcakt number: for tx */
					sf.pkt_num = atoi(optarg);
					break;

				case 'g': /* time gap: for tx */
					sf.delay = atoi(optarg) * 1000;
					break;

				case 'h':
					default
						:
						print_help();
					break;
			}

			if(opt == 255)
				break;
		}


		printf("%s %d-%d\n", buf, sf.saddr.sin_addr, sf.daddr.sin_addr);
		if(!strcmp(buf, "rsnd"))
			res = OPT_RAW_SND;

		if(!strcmp(buf, "rrcv"))
			res = OPT_RAW_RCV;

		if(!strcmp(buf, "ping"))
			res = OPT_SYN_PING;

		printf("res = %d\n", res);

		return res;
	}



	int main(int argc, char *argv[])
	{
		int opt = 0;
		memset((void *) &sf, 0, sizeof(struct sch_config));

		if((opt = get_conf(argc, argv)) == 0) {
			printf("Error input paramaters.\n");
			print_help();
			return 0;
		}
		printf("test1\n");
		switch(opt) {
			case OPT_RAW_SND:
				printf("Packet tx test.\n");
				raw_tx_test();
				break;
			case OPT_RAW_RCV:
				raw_rx_test();
				break;
			case OPT_SYN_PING:
				syn_ping(sf.delay);
				break;
			default:
				break;
		}
		return 0;
	}
