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

#include "server.h"

unsigned char dns_resolvers[10][256];
unsigned char root_servers[13][256];

int main() {
	// Disable output buffering
	setbuf(stdout, NULL);
 	setbuf(stderr, NULL);

	// Start Logging the outputs
    printf("Logs from this program will appear here!\n");

	// Get the names of standard DNS resolvers and Root name servers
	getDNSresolvers();

	// unsigned char host[256];
	// strcpy((char *)host, "academy.networkchuck.com");
	// int qtype = 1;
	// dns_resource_record_t *dns = getHostByName(host, qtype);
	// if (dns != NULL)
	// 	printf("The IP address of %s is : %s\n", host, dns->rdata);

	// Creating a UDP socket
	int socket_desc = socket(AF_INET, SOCK_DGRAM, 0);
	if (socket_desc == -1){
		printf("Socket creation failed : %s...\n", strerror(errno));
		return 1;
	}

	int reuse = 1;
	if (setsockopt(socket_desc, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0){
		printf("SO_REUSEPORT failed: %s...\n", strerror(errno));
		return 1;
	}

	struct sockaddr_in serv_addr;
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(2053);
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	// Bind the socket to the address
	if (bind(socket_desc, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) != 0){
		printf("Bind failed : %s...\n", strerror(errno));
		return 1;
	}

	int bytesRead;
	unsigned char buf[65536], *qname;
	dns_query_info_t *qinfo;
	struct sockaddr_in clientAddress;
	socklen_t clientAddrLen = sizeof(clientAddress);

	while(1){
		bytesRead = recvfrom(socket_desc, buf, 65536, 0, (struct sockaddr *) &clientAddress, &clientAddrLen);
		if (bytesRead == -1){
			perror("Error receiving data");
			break;
		}

		buf[bytesRead] = '\0';
		printf("Received %d bytes : %s\n", bytesRead, buf);

		dns_header_t *header = (dns_header_t *) &buf;
		qname = (unsigned char *) &buf[sizeof(header)];
		qinfo = (dns_query_info_t *) &buf[sizeof(header) + strlen(qname) + 1];

		int size = sizeof(header) + strlen(qname) + 1 + sizeof(dns_query_info_t);

		dns_resource_record_t *result = getHostByName(qname, ntohs(qinfo->type));

		if (result == NULL){
			// Hum pe to hai hi na, ask someone else
			result = getHostFromResolver(qname, ntohs(qinfo->type));
		}

		if (result == NULL){
			// If no one has it, then probably the domain itself if not valid
			header->flags = 0;
			header->flags |= 3; 	// Non-existent domain
			header->flags |= QR_MASK;
			header->flags |= RA_MASK;
			header->flags = htons(header->flags);
		}
		else{
			header->flags = 0;
			header->flags |= QR_MASK;
			header->flags |= RA_MASK;
			header->flags = htons(header->flags);

			header->qcount = 0;
			header->ancount = ntohs(1);
			header->nscount = 0;
			header->arcount = 0;

			dns_resource_record_t *answer = (dns_resource_record_t *) &buf[size];
			strcpy(answer->name, qname);
			size += strlen(qname) + 1;

			memcpy(answer->resource, result->resource, sizeof(dns_resource_data_t));
			size += sizeof(dns_resource_data_t);

			memcpy(answer->name, result->rdata, INET_ADDRSTRLEN);	// Copy the whole encoded address
			size += INET_ADDRSTRLEN;
		}

		// Send the response back
		if (sendto(socket_desc, &buf, size, 0, (struct sockaddr *) & clientAddress, clientAddrLen) == -1){
			perror("Error sending response");
		}

		printf("Query response sent successfully");

		free(result);
	}

	close(socket_desc);
	return 0;
}

dns_resource_record_t* getHostFromResolver(unsigned char *host, int qtype){
	int i;
	dns_resource_record_t *answer;
	for (i = 0; i < 2; i++){
		answer = getHostByNameAndDest(host, qtype, dns_resolvers[i]);
		if (answer != NULL)
			return answer;
	}
	return NULL;
}

void packDNSQuery(unsigned char *host, int qtype, unsigned char *buf, int *query_len, dns_header_t **header){
	dns_query_info_t *qinfo;
	unsigned char *qname;

	*header = (dns_header_t *) buf;
	(*header)->id = (uint16_t) htons(getpid());
	
	(*header)->flags = 0;
	(*header)->flags |= RD_MASK;
	(*header)->flags = htons((*header)->flags);
	
	(*header)->qcount = htons(1);
	(*header)->ancount = 0;
	(*header)->nscount = 0;
	(*header)->arcount = 0;

	*query_len += sizeof(dns_header_t);

	// qname = (unsigned char *) &buf[*query_len];	// Point to right after the header
	qname = (unsigned char *) (buf + *query_len);
	changeToDNSNameFormat(qname, host);
	*query_len += strlen(qname) + 1;

	qinfo = (dns_query_info_t *) &buf[*query_len];
	qinfo->type = htons(qtype);
	qinfo->class = htons(1); 	// for internet
	*query_len += sizeof(dns_query_info_t);
}

void unpackDNSResponse(unsigned char *buf, dns_resource_record_t *answer, dns_resource_record_t *auth, 
	dns_resource_record_t *addit, dns_header_t **header)
{
	dns_query_info_t *qinfo;
	unsigned char *qname, *reader;
	int i, j, gain;

	*header = (dns_header_t *) buf;
	qname = (unsigned char *) (buf + sizeof(dns_header_t));	// Point to right after the header
	qinfo = (dns_query_info_t *) &buf[sizeof(dns_header_t) + strlen(qname) + 1];

	reader = (unsigned char *) (buf + sizeof(dns_header_t) + strlen(qname) + 1 + sizeof(dns_query_info_t));

	printf("The response is as follows....");
	printf(" %d questions", ntohs((*header)->qcount));
	printf(" %d answers", ntohs((*header)->ancount));
	printf(" %d Authoritative servers", ntohs((*header)->nscount));
	printf(" %d additional records\n", ntohs((*header)->arcount));

	// Read answers section
	for (i = 0; i < ntohs((*header)->ancount); i++){
		answer[i].name = readNameFromDNSFormat(reader, buf, &gain);
		reader += gain;

		answer[i].resource = (dns_resource_data_t *) reader;
		reader += sizeof(dns_resource_data_t);

		if (ntohs(answer[i].resource->type) == A_MASK || ntohs(answer[i].resource->type) == AAAA_MASK){
			answer[i].rdata = (unsigned char*) malloc(ntohs(answer[i].resource->rdlength));
			for (j = 0; j < ntohs(answer[i].resource->rdlength); j++){
				answer[i].rdata[j] = reader[j];
			}
			answer[i].rdata[ntohs(answer[i].resource->rdlength)] = '\0';
			reader += ntohs(answer[i].resource->rdlength);
		}
		else{
			answer[i].rdata = readNameFromDNSFormat(reader, buf, &gain);
			reader += gain;
		}
	}

	// Read Authority section
	for (i = 0; i < ntohs((*header)->nscount); i++){
		auth[i].name = readNameFromDNSFormat(reader, buf, &gain);
		reader += gain;

		auth[i].resource = (dns_resource_data_t *) reader;
		reader += sizeof(dns_resource_data_t);

		if (ntohs(auth[i].resource->type) == A_MASK || ntohs(auth[i].resource->type) == AAAA_MASK){
			auth[i].rdata = (unsigned char*) malloc(ntohs(auth[i].resource->rdlength));
			for (j = 0; j < ntohs(auth[i].resource->rdlength); j++){
				auth[i].rdata[j] = reader[j];
			}
			auth[i].rdata[ntohs(auth[i].resource->rdlength)] = '\0';
			reader += ntohs(auth[i].resource->rdlength);
		}
		else{
			auth[i].rdata = readNameFromDNSFormat(reader, buf, &gain);
			reader += gain;
		}
	}

	// Read Additional records section
	for (i = 0; i < ntohs((*header)->arcount); i++){
		addit[i].name = readNameFromDNSFormat(reader, buf, &gain);
		reader += gain;

		addit[i].resource = (dns_resource_data_t *) reader;
		reader += sizeof(dns_resource_data_t);

		if (ntohs(addit[i].resource->type) == A_MASK || ntohs(addit[i].resource->type) == AAAA_MASK){
			addit[i].rdata = (unsigned char*) malloc(ntohs(addit[i].resource->rdlength));
			for (j = 0; j < ntohs(addit[i].resource->rdlength); j++){
				addit[i].rdata[j] = reader[j];
			}
			addit[i].rdata[ntohs(addit[i].resource->rdlength)] = '\0';
			reader += ntohs(addit[i].resource->rdlength);
		}
		else{
			addit[i].rdata = readNameFromDNSFormat(reader, buf, &gain);
			reader += gain;
		}
	}
}

void printRecord(dns_resource_record_t *answer){
	int i;
	char ipv4[INET_ADDRSTRLEN], ipv6[INET6_ADDRSTRLEN];
	printf("%s %d %d %d %d ", answer->name, ntohs(answer->resource->type), ntohs(answer->resource->class),
		ntohs(answer->resource->ttl), ntohs(answer->resource->rdlength));

	if (ntohs(answer->resource->type) == A_MASK){
		inet_ntop(AF_INET, answer->rdata, ipv4, INET_ADDRSTRLEN);
		printf("%s\n", ipv4);
	}
	else if (ntohs(answer->resource->type) == AAAA_MASK){
		inet_ntop(AF_INET6, answer->rdata, ipv6, INET6_ADDRSTRLEN);
		printf("%s\n", ipv6);
	}
	else
		printf("%s\n", answer->rdata);
}

void printRecords(dns_resource_record_t *answer, int count){
	int i;
	char ipv4[INET_ADDRSTRLEN], ipv6[INET6_ADDRSTRLEN];
	for (i = 0; i < count; i++){
		printRecord(&answer[i]);
	}
}

dns_resource_record_t* getHostByNameAndDest(unsigned char *host, int qtype, unsigned char *dest){
	unsigned char buf[65536], *qname, *reader, ipv4[INET_ADDRSTRLEN];
	dns_header_t *header;
	dns_query_info_t *qinfo;

	int socket_desc, i, j, gain, dest_len, query_len = 0;
	struct sockaddr_in dest_addr;
	struct timeval timeout;

	dns_resource_record_t answer[16], auth[16], addit[16], *result = NULL;

	socket_desc = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (socket_desc == -1){
		printf("Socket creation failed : %s...\n", strerror(errno));
		return NULL;
	}

	// Set receive timeout
    timeout.tv_sec = 5;  // 5 second timeout
    timeout.tv_usec = 0;
    if (setsockopt(socket_desc, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("Error setting socket timeout");
		goto resmark;
    }

	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(53);
    if (inet_pton(AF_INET, dest, &dest_addr.sin_addr) <= 0) {
        printf("Invalid DNS resolver address: %s\n", dns_resolvers[0]);
		goto resmark;
    }

	dest_len = sizeof(dest_addr);

	packDNSQuery(host, qtype, buf, &query_len, &header);

	if (sendto(socket_desc, (char *)buf, query_len, 0, (struct sockaddr *) &dest_addr, (socklen_t) dest_len) < 0)
	{
		perror("Error sending query");
		goto resmark;
	}
	printf("DNS query sent\n");

	if (recvfrom(socket_desc, (char *)buf, 65535, 0, (struct sockaddr *) &dest_addr, (socklen_t *) &dest_len) < 0){
		perror("Error receiving query response");
		goto resmark;
	}
	printf("DNS query response received successfully\n");

	unpackDNSResponse(buf, answer, auth, addit, &header);

	printRecords(answer, ntohs(header->ancount));
	printRecords(auth, ntohs(header->nscount));
	printRecords(addit, ntohs(header->arcount));

	for (i = 0; i < ntohs(header->ancount); i++){
		if (ntohs(answer[i].resource->type) == qtype){
			// We got the answer. Return this
			result = (dns_resource_record_t *) malloc(sizeof(dns_resource_record_t));
			
			result->name = (unsigned char *) malloc(strlen(answer[i].name) + 1);
			strcpy(result->name, answer[i].name);

			result->resource = (dns_resource_data_t *) malloc(sizeof(dns_resource_data_t));
			memcpy(result->resource, answer[i].resource, sizeof(dns_resource_data_t));

			result->rdata = (unsigned char *) malloc(INET_ADDRSTRLEN);
			if (inet_ntop(AF_INET, answer[i].rdata, result->rdata, INET_ADDRSTRLEN) == NULL) {
				perror("Address conversion failed");
				continue;
			}

			goto resmark;
		}
		else if (answer[i].resource->type = CNAME_MASK){
			// Query this cname again to the same destination to get the required address
			result = getHostByNameAndDest(answer[i].rdata, qtype, dest);
			if (result != NULL)
				goto resmark;
		}
		else{
			// Not what we want
			continue;
		}
	}

	for (i = 0; i < ntohs(header->nscount); i++){
		if (auth[i].rdata){
			for (j = 0; j < ntohs(header->arcount); j++){
				if (ntohs(addit[j].resource->type) == A_MASK && strcmp(addit[j].name, auth[i].rdata) == 0){
					if (inet_ntop(AF_INET, addit[j].rdata, ipv4, INET_ADDRSTRLEN) == NULL) {
						perror("Address conversion failed");
						continue;
					}

					result = getHostByNameAndDest(host, qtype, (unsigned char *) ipv4);
					if (result != NULL)
						goto resmark;
				}
			}
		}
	}

resmark:
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
	return result;
}

dns_resource_record_t* getHostByName(unsigned char* host, int qtype){
	int i;
	dns_resource_record_t *answer;
	for (i = 0; i < 13; i++){
		answer = getHostByNameAndDest(host, qtype, root_servers[i]);
		if (answer != NULL)
			return answer;
	}
	return NULL;
}

unsigned char* readNameFromDNSFormat(unsigned char *reader, unsigned char *buf, int *gain){
	unsigned char *name;
	int i, j, offset, ptr = 0, jump = 0;

	name = (unsigned char*)malloc(256);
	name[0] = '\0';
	*gain = 1;

	// Get the whole name in DNS format
	while(*reader != 0){
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
		reader++ ;

		if (!jump)
			(*gain)++ ;
	}
	name[ptr] = '\0';
	if (jump)
		(*gain)++ ;

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

	strcpy(root_servers[0], "198.41.0.4");
	strcpy(root_servers[1], "170.247.170.2");
	strcpy(root_servers[2], "192.33.4.12");
	strcpy(root_servers[3], "199.7.91.13");
	strcpy(root_servers[4], "192.203.230.10");
	strcpy(root_servers[5], "192.5.5.241");
	strcpy(root_servers[6], "192.112.36.4");
	strcpy(root_servers[7], "198.97.190.53");
	strcpy(root_servers[8], "192.36.148.17");
	strcpy(root_servers[9], "192.58.128.30");
	strcpy(root_servers[10], "193.0.14.129");
	strcpy(root_servers[11], "199.7.83.42");
	strcpy(root_servers[12], "202.12.27.33");
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