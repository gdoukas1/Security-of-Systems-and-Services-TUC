#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>	
#include <netinet/tcp.h>	

long int Network_flows=0, Tcp_flows=0, Udp_flows=0, Total_packets=0, Total_tcps=0, Total_udps=0, Total_bytes_tcp=0, Total_bytes_udp=0;

typedef struct net_flow{
	char source_ip[INET_ADDRSTRLEN];
	char dest_ip[INET_ADDRSTRLEN];
	unsigned int protocol;
	unsigned int sport;
	unsigned int dport;

	struct net_flow* next;

}n_flow;

typedef struct retransmission{

	char source_ip[INET_ADDRSTRLEN];
	char dest_ip[INET_ADDRSTRLEN];
	int payload;
	struct tcphdr *tcp;

	struct retransmission* next;

}retransm;


n_flow* net = NULL;
retransm* retrans_glb = NULL;
retransm* current_flow = NULL;


void
usage(void){
	printf(
	       "\n"
	       "Usage:\n"
	       "\t./monitor \n"
		   "Options:\n"
		   "-r, Packet capture file name (e.g. test.pcap)\n"
		   "-h, Help message\n\n"
		   );
	exit(EXIT_FAILURE);
}


void 
statistics(){

	printf("\na. Total number of network flows captured: %ld\n",Network_flows);
	printf("b. Number of TCP network flows captured: %ld\n",Tcp_flows);
	printf("c. Number of UDP network flows captured: %ld\n",Udp_flows);
	printf("d. Total number of packets received: %ld\n",Total_packets);
	printf("e. Total number of TCP packets received: %ld\n",Total_tcps);
	printf("f. Total number of UDP packets received: %ld\n",Total_udps);
	printf("g. Total bytes of TCP packets received: %ld\n",Total_bytes_tcp);
	printf("h. Total bytes of UDP packets received: %ld\n",Total_bytes_udp);
}

n_flow * 
in_list(n_flow * netf, char* ips, char* ipd, int prtc, unsigned int sprt, unsigned int dprt){
	n_flow* tmp = netf;
    while(tmp != NULL){

        if(tmp->protocol == prtc && tmp->sport == sprt && tmp->dport == dprt && strcmp(tmp->source_ip,ips)==0 && strcmp(tmp->dest_ip,ipd)==0){
            return tmp;
        }
        tmp = tmp->next;
    }
    return NULL;
}

void 
new_net(n_flow * netf, char* ips, char* ipd, int prtc, unsigned int sprt, unsigned int dprt){

	n_flow* new = (n_flow*)malloc(sizeof(n_flow));
	n_flow* tmp = netf;

	while(tmp->next != NULL){
		tmp = tmp->next;
	}

	tmp->next = new;
	memcpy(new->source_ip, ips, INET_ADDRSTRLEN);
	memcpy(new->dest_ip, ipd, INET_ADDRSTRLEN);
	new->protocol = prtc;
	new->sport    = sprt;
	new->dport    = dprt;
	new->next 	  = NULL;

	Network_flows++;
	if(new->protocol == IPPROTO_TCP)
		Tcp_flows++;
	else if (new->protocol == IPPROTO_UDP)
		Udp_flows++;
    else
        printf("Other protocol than TCP or UDP");

    return;
}

retransm* 
add_to_current_flow(retransm* head ,retransm* new){

	if(new == NULL)
	 return head;
	
	if(head == NULL){
		head = new; 
		return head;}
	else{
		retransm* temp = head;
		while(temp->next != NULL)		
			temp = temp->next;

		temp->next = new;
	}
	return head;
}	


retransm* 
add_transmission(retransm* head ,retransm* new){	
	
	current_flow = NULL;

	if(new == NULL)
		return head;
	
	if(head == NULL){
		 head = new;
		 return head;}
	else{
		retransm* temp = head;
		
		while(temp->next != NULL){
			if(strcmp(temp->source_ip, new->source_ip)== 0 && strcmp(temp->dest_ip, new->dest_ip)== 0 
                && ntohs(new->tcp->source) == ntohs(temp->tcp->source) 
                && ntohs(new->tcp->dest) == ntohs(temp->tcp->dest)){			

				retransm* current;
				current=(retransm*)malloc(sizeof(retransm));
				
				current->tcp = temp->tcp;
				strcpy(current->source_ip, temp->source_ip);
				strcpy(current->dest_ip, temp->dest_ip);
				current->payload = temp->payload;
				current->next = NULL;
				
				current_flow = add_to_current_flow(current_flow,current);					
			}		
			temp = temp->next;
		}
		temp->next = new;	
	}
	
	if(current_flow != NULL){

		while(current_flow->next != NULL){

			if((current_flow->tcp->seq-1 != new->tcp->ack_seq) && (new->tcp->syn == 1 || new->tcp->fin == 1 || new->payload>0 ) &&
			   (current_flow->tcp->seq + current_flow->payload > new->tcp->seq) && new->tcp->ack == 1){
				printf("[TCP RETRANSMISSION]\n\n"); 
				break;
			}
			current_flow = current_flow->next;	
		}
	}
	
	return head;
}

void 
check_retransmission( char* ips,char* ipd, struct tcphdr *tcph,int payload){
	retransm* tmp_retr ;

    tmp_retr=(retransm*)malloc(sizeof(retransm));
    memcpy(tmp_retr->source_ip, ips, INET_ADDRSTRLEN);
    memcpy(tmp_retr->dest_ip, ipd, INET_ADDRSTRLEN);


    tmp_retr->payload = payload;
    tmp_retr->tcp = tcph;
    tmp_retr->next = NULL;

    retrans_glb = add_transmission(retrans_glb,tmp_retr);
    return;
}


void 
tcp_info(const u_char *packet, int size)
{
	n_flow* tmp_flow = NULL;
	char src_ip[INET_ADDRSTRLEN];
	char dst_ip[INET_ADDRSTRLEN];
	unsigned short ip_len;
	const struct ip * iphead = (struct ip *)(packet  + sizeof(struct ethhdr) );

	struct ether_header *e_ptr = (struct ether_header*)packet;

	if (ntohs(e_ptr->ether_type) != ETHERTYPE_IP && ntohs(e_ptr->ether_type) != ETHERTYPE_IPV6) {
		printf("Not an IPv4 nor IPv6 packet. Skipped\n");
		return;
	}
	ip_len = iphead->ip_hl*4;
	
	inet_ntop(AF_INET, &(iphead->ip_src), src_ip, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(iphead->ip_dst), dst_ip, INET_ADDRSTRLEN);
	
	struct tcphdr *tcph=(struct tcphdr*)(packet + ip_len + sizeof(struct ethhdr));

	int header_size =  sizeof(struct ethhdr) + ip_len + tcph->doff*4;
	int payload_length = size - header_size;
	Total_bytes_tcp = Total_bytes_tcp + size;

	if (net==NULL){
		tmp_flow=(n_flow*)malloc(sizeof(n_flow));
		memcpy(tmp_flow->source_ip,src_ip,INET_ADDRSTRLEN);
		memcpy(tmp_flow->dest_ip,dst_ip,INET_ADDRSTRLEN);

		tmp_flow->protocol = (unsigned int)iphead->ip_p;
		tmp_flow->sport    = ntohs(tcph->source);
		tmp_flow->dport	   = ntohs(tcph->dest);
		tmp_flow->next 	   = NULL;
		net = tmp_flow;

		Network_flows++;
		Tcp_flows++;

	}else{
		if((tmp_flow = in_list(net, src_ip, dst_ip, (unsigned int)iphead->ip_p, ntohs(tcph->source), ntohs(tcph->dest))) == NULL)
			new_net(net,src_ip,dst_ip,(unsigned int)iphead->ip_p,ntohs(tcph->source),ntohs(tcph->dest));
		}


	printf("|Source IP: %s| |Dest. IP: %s| |Protocol: TCP| ",src_ip, dst_ip);
	printf("|Source Port: %u| |Dest. Port: %u| |Header Length: %d| |Payload Length: %d|\n",ntohs(tcph->source),ntohs(tcph->dest),(unsigned int)tcph->doff*4, payload_length);
	
	check_retransmission(src_ip,dst_ip,tcph,payload_length);

	return;
}

void 
udp_info(const u_char * packet, int size)
{

	n_flow* tmp_flow = NULL;
	char src_ip[INET_ADDRSTRLEN];
	char dst_ip[INET_ADDRSTRLEN];
	unsigned short ip_len;

	const struct ip * iphead = (struct ip *)(packet  + sizeof(struct ethhdr) );
	struct ether_header *e_ptr = (struct ether_header*)packet;

	if (ntohs(e_ptr->ether_type) != ETHERTYPE_IP && ntohs(e_ptr->ether_type) != ETHERTYPE_IPV6) {
		printf("Not an IPv4 nor IPv6 packet. Skipped\n");
		return;
	}
	ip_len = iphead->ip_hl*4;
	
	inet_ntop(AF_INET, &(iphead->ip_src), src_ip, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(iphead->ip_dst), dst_ip, INET_ADDRSTRLEN);
	

	struct udphdr *udph=(struct udphdr*)(packet + ip_len + sizeof(struct ethhdr));

	int header_size =  sizeof(struct ethhdr) + ip_len + sizeof(udph);
	int payload_length = size - header_size;

	Total_bytes_udp = Total_bytes_udp + size;

	if (net==NULL){

		tmp_flow=(n_flow*)malloc(sizeof(n_flow));
		memcpy(tmp_flow->source_ip,src_ip,INET_ADDRSTRLEN);
		memcpy(tmp_flow->dest_ip,dst_ip,INET_ADDRSTRLEN);

		tmp_flow->protocol = (unsigned int)iphead->ip_p;
		tmp_flow->sport    = ntohs(udph->source);
		tmp_flow->dport	   = ntohs(udph->dest);
		tmp_flow->next 	   = NULL;
		net = tmp_flow;

		Network_flows++;
		Udp_flows++;

	}else{
		if((tmp_flow = in_list(net,src_ip,dst_ip,(unsigned int)iphead->ip_p,ntohs(udph->source),ntohs(udph->dest)))==NULL)
			new_net(net,src_ip,dst_ip,(unsigned int)iphead->ip_p,ntohs(udph->source),ntohs(udph->dest));
	}

	printf("|Source IP: %s| |Dest. IP: %s| |Protocol: UDP| ",src_ip, dst_ip);
	printf("|Source Port: %u| |Dest. Port: %u| |Header Length: %d| |Payload Length: %d|\n",ntohs(udph->source),ntohs(udph->dest),(unsigned int)udph->len, payload_length);
	
	return;
}


void 
packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const u_char *packet){
	
    int size = header->caplen;

	struct iphdr *ip = (struct iphdr*)(packet + sizeof(struct ethhdr));
	Total_packets++;
	switch (ip->protocol) 
	{
		case IPPROTO_TCP: 
			++Total_tcps;
			tcp_info(packet, size);
			break;
		
		case IPPROTO_UDP: 
			++Total_udps;
			udp_info(packet, size);
			break;
		default: 
			break;		
	}
    return;
}

void
pcap_file_capture(char *filename){
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];  //error buffer

    handle = pcap_open_offline(filename, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error: %s\nCouldn't read the file: %s\n", errbuf, filename);
        exit(EXIT_FAILURE);
    }
    pcap_loop(handle,-1,packet_handler,NULL);

    //cleanup
    retransm* tr;
    while(retrans_glb != NULL){
        tr = retrans_glb->next;
        free(retrans_glb);
        retrans_glb = tr;
    }
    pcap_close(handle);
    return;
}


int
main(int argc, char *argv[]){   
    int opt;
    u_char *input_file = NULL;

    if (argc < 2)
        usage();

    while ((opt = getopt(argc, argv, "hr:")) != -1) {
		switch (opt) {
		case 'r':
			input_file = strdup(optarg);
			pcap_file_capture(input_file);
            statistics();
            break;
		case 'h':
            usage();
            break;
		default:
            usage();
        }
    }

    argc -= optind;
	argv += optind;	
	return 0;
}