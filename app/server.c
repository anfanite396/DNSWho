#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <arpa/inet.h>

#define QR_MASK 	0x8000
#define OPCODE_MASK 0x7800
#define AA_MASK 	0x0400
#define TC_MASK 	0x0200
#define RD_MASK 	0x0100
#define RA_MASK 	0x0080
#define Z_MASK 		0x0070
#define RCODE_MASK 	0x000F

typedef struct{
	uint16_t id;
	uint16_t flags;
	uint16_t qcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} dns_header_t;

typedef struct{
	unsigned short type;
	unsigned short class;
} dns_query_info_t;

typedef struct{
	uint8_t type;
	uint8_t class;
	uint16_t ttl;
	uint8_t rdlength; 
} dns_resource_data_t;

typedef struct{
	unsigned char *name;
	dns_resource_data_t *resource;
	unsigned char *rdata;
} dns_resource_record_t;

void getHostByName(unsigned char* host, int qtype);
void changeToDNSNameFormat(unsigned char *dns, unsigned char *host);
void getDNSresolvers();
unsigned char* readNameFromDNSFormat(unsigned char *reader, unsigned char *buf, int *gain);

unsigned char dns_resolvers[10][256];

int main() {
	// Disable output buffering
	setbuf(stdout, NULL);
 	setbuf(stderr, NULL);

	// Start Logging the outputs
    printf("Logs from your program will appear here!\n");

	// Get the names of possible DNS resolvers
	getDNSresolvers();

	unsigned char host[256];
	strcpy((char *)host, "www.google.com");
	int qtype = 1;
	getHostByName(host, qtype);

	// // Creating a UDP socket
	// int socket_desc = socket(AF_INET, SOCK_DGRAM, 0);
	// if (socket_desc == -1){
	// 	printf("Socket creation failed : %s...\n", strerror(errno));
	// 	return 1;
	// }

	// int reuse = 1;
	// if (setsockopt(socket_desc, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0){
	// 	printf("SO_REUSEPORT failed: %s...\n", strerror(errno));
	// 	return 1;
	// }

	// struct sockaddr_in serv_addr;
	// serv_addr.sin_family = AF_INET;
	// serv_addr.sin_port = htons(2053);
	// serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	// // Bind the socket to the address
	// if (bind(socket_desc, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) != 0){
	// 	printf("Bind failed : %s...\n", strerror(errno));
	// 	return 1;
	// }

	// int bytesRead;
	// char buffer[512];
	// struct sockaddr_in clientAddress;
	// socklen_t clientAddrLen = sizeof(clientAddress);

	// while(1){
	// 	bytesRead = recvfrom(socket_desc, buffer, sizeof(buffer), 0, (struct sockaddr *) &clientAddress, &clientAddrLen);
	// 	if (bytesRead == -1){
	// 		perror("Error receiving data");
	// 		break;
	// 	}

	// 	buffer[bytesRead] = '\0';
	// 	printf("Received %d bytes : %s\n", bytesRead, buffer);

	// 	dns_message_t response = {0};
	// 	response.header.id = htons(1234);
	// 	response.header.flags |= QR_MASK;
	// 	response.header.flags = htons(response.header.flags);

	// 	// Send response
	// 	if (sendto(socket_desc, &response, sizeof(response), 0, (struct sockaddr *) &clientAddress, clientAddrLen) == -1){
	// 		perror("Error sending response");
	// 	}
	// }

	// close(socket_desc);
	return 0;
}

void getHostByName(unsigned char* host, int qtype){
	unsigned char buf[65536], *qname, *reader;
	dns_query_info_t *qinfo;

	int socket_desc, i, j, gain, dest_len;
	struct sockaddr_in dest;
	struct timeval timeout;

	dns_resource_record_t answer[16], auth[16], addit[16];

	socket_desc = socket(AF_INET, SOCK_DGRAM, 0);
	if (socket_desc == -1){
		printf("Socket creation failed : %s...\n", strerror(errno));
		return;
	}

	// Set receive timeout
    timeout.tv_sec = 5;  // 5 second timeout
    timeout.tv_usec = 0;
    if (setsockopt(socket_desc, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("Error setting socket timeout");
        close(socket_desc);
        return;
    }

	dest.sin_family = AF_INET;
	dest.sin_port = htons(53);
    if (inet_pton(AF_INET, dns_resolvers[0], &dest.sin_addr) <= 0) {
        printf("Invalid DNS resolver address: %s\n", dns_resolvers[0]);
        close(socket_desc);
        return;
    }

	dest_len = sizeof(dest);

	dns_header_t *header = (dns_header_t *) &buf;
	header->id = (uint16_t) htons(getpid());
	
	header->flags = 0;
	header->flags |= QR_MASK;
	header->flags |= RD_MASK;
	header->flags = htons(header->flags);
	
	header->qcount = htons(1);
	header->ancount = 0;
	header->nscount = 0;
	header->arcount = 0;

	qname = (unsigned char *) &buf[sizeof(dns_header_t)];	// Point to right after the header
	changeToDNSNameFormat(qname, host);

	qinfo = (dns_query_info_t *) &buf[sizeof(dns_header_t) + strlen(qname) + 1];
	qinfo->type = qtype;
	qinfo->class = 1; 	// for internet

	int size = sizeof(dns_header_t) + strlen(qname) + 1 + sizeof(dns_query_info_t);
	if (sendto(socket_desc, &buf, sizeof(dns_header_t) + strlen(qname) + 1 + sizeof(dns_query_info_t), 0,
			(struct sockaddr *) &dest, (socklen_t) sizeof(dest)) < 0)
	{
		perror("Error sending query");
		close(socket_desc);
		return;
	}
	printf("DNS query sent\n");

	if (recvfrom(socket_desc, &buf, 65536, 0, (struct sockaddr *) &dest, (socklen_t *) &dest_len) < 0){
		perror("Error receiving query response");
		close(socket_desc);
		return;
	}
	printf("DNS query response received successfully\n");

	header = (dns_header_t *) &buf;
	qname = qname = (unsigned char *) &buf[sizeof(dns_header_t)];	// Point to right after the header
	qinfo = (dns_query_info_t *) &buf[sizeof(dns_header_t) + strlen(qname) + 1];

	reader = &buf[sizeof(dns_header_t) + strlen(qname) + 1 + sizeof(dns_query_info_t)];

	printf("The response is as follows....");
	printf(" %d questions", ntohs(header->qcount));
	printf(" %d answers", ntohs(header->ancount));
	printf(" %d Authoritative servers", ntohs(header->nscount));
	printf(" %d additional records\n", ntohs(header->arcount));

	// Read answers section
	gain = 0;
	for (i = 0; i < ntohs(header->ancount); i++){
		answer[i].name = readNameFromDNSFormat(reader, buf, &gain);
		reader += gain;

		answer[i].resource = (dns_resource_data_t *) reader;
		reader += sizeof(dns_resource_data_t);

		if (answer[i].resource->type == 1){
			answer[i].rdata = (unsigned char*) malloc(ntohs(answer[i].resource->rdlength));
			for (j = 0; j < ntohs(answer[i].resource->rdlength); j++){
				answer[i].rdata[j] = reader[j];
			}
			reader += ntohs(answer[i].resource->rdlength);
		}
		else{
			answer[i].rdata = readNameFromDNSFormat(reader, buf, &gain);
			reader += gain;
		}
	}

	// Read Authority section
	gain = 0;
	for (i = 0; i < ntohs(header->ancount); i++){
		auth[i].name = readNameFromDNSFormat(reader, buf, &gain);
		reader += gain;

		auth[i].resource = (dns_resource_data_t *) reader;
		reader += sizeof(dns_resource_data_t);

		if (auth[i].resource->type == 1){
			auth[i].rdata = (unsigned char*) malloc(ntohs(auth[i].resource->rdlength));
			for (j = 0; j < ntohs(auth[i].resource->rdlength); j++){
				auth[i].rdata[j] = reader[j];
			}
			reader += ntohs(auth[i].resource->rdlength);
		}
		else{
			auth[i].rdata = readNameFromDNSFormat(reader, buf, &gain);
			reader += gain;
		}
	}

	// Read Additional records section
	gain = 0;
	for (i = 0; i < ntohs(header->ancount); i++){
		addit[i].name = readNameFromDNSFormat(reader, buf, &gain);
		reader += gain;

		addit[i].resource = (dns_resource_data_t *) reader;
		reader += sizeof(dns_resource_data_t);

		if (addit[i].resource->type == 1){
			addit[i].rdata = (unsigned char*) malloc(ntohs(addit[i].resource->rdlength));
			for (j = 0; j < ntohs(addit[i].resource->rdlength); j++){
				addit[i].rdata[j] = reader[j];
			}
			reader += ntohs(addit[i].resource->rdlength);
		}
		else{
			addit[i].rdata = readNameFromDNSFormat(reader, buf, &gain);
			reader += gain;
		}
	}

	for (i = 0; i < ntohs(header->ancount); i++){
		if (answer[i].name)
			free(answer[i].name);
		if (answer[i].rdata)
			free(answer[i].rdata);
	}

	for (i = 0; i < ntohs(header->nscount); i++){
		if (auth[i].name)
			free(auth[i].name);
		if (auth[i].rdata)
			free(auth[i].rdata);
	}

	for (i = 0; i < ntohs(header->arcount); i++){
		if (addit[i].name)
			free(addit[i].name);
		if (addit[i].rdata)
			free(addit[i].rdata);
	}

	close(socket_desc);
}

unsigned char* readNameFromDNSFormat(unsigned char *reader, unsigned char *buf, int *gain){
	unsigned char *name;
	int i, j, offset, ptr = 0, jump = 0;

	name = (unsigned char*)malloc(256);
	name[0] = '\0';
	*gain = 0;

	// Get the whole name in DNS format
	while(*reader != '\0'){
		if (*reader >= 192){
			// Offset is of the form 11000000 00000000
			offset = (((*reader) & 0x3F) << 8) | (*(reader + 1)); 	// get the last 14bits;
			reader = buf + offset - 1;
			jump++ ; 	// We jump from here

			if (jump > 15){
				printf("Too many jumps in DNS name parsing... terminating\n");
				free(name);
				return NULL;
			}
		}
		else{
			name[ptr++] = *reader;
		}

		if (!jump)
			(*gain)++ ;
	}
	name[ptr] = '\0';
	if (jump)
		(*gain) += 2;

	// Now convert from DNS format to original format
	for (i = 0; i < strlen(name); i++){
		ptr = name[i];
		for (j = i; j < i + ptr; j++){
			name[j] = name[j + 1];
		}
		name[i + ptr] = '.';
		i += ptr;
	}
	name[i - 1] = '\0';		// Remove the last '.'

	return name;
}

void getDNSresolvers(){
	strcpy(dns_resolvers[0], "1.1.1.1");
	strcpy(dns_resolvers[1], "8.8.8.8");
}

void changeToDNSNameFormat(unsigned char* dns, unsigned char* host){
	int i = 0, j = 0;
	strcat((char*)host, ".");

	for (i = 0; i < strlen((char*)host); i++){
		if (host[i] == '.'){
			*dns++ = i - j;
			for (j; j < i; j++){
				*dns++ = host[j];
			}
			j++ ;
		}
	}
	*dns++ = '\0';
}