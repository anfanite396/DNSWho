#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "server.h"

#define PORT 2053

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

int main(){
    int sock_desc = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_desc < 0){
        perror("Socket creation failed");
        return 1;
    }

    unsigned char buf[65536];
    struct sockaddr_in serv_addr;
    unsigned char host[256], dest[256];
    dns_resource_record_t *dns;
    int qtype = 1;

	init_openssl();

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(853);
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0){
        perror("Invalid server IP");
        close(sock_desc);
        return 1;
    }

    strcpy((char *)dest, "127.0.0.1");

    while(1){
        scanf("%s", (unsigned char *) &host);
        dns = getHostByNameAndDest(host, qtype, dest);
        if (dns != NULL)
            printf("The IP address of %s is : %s\n", host, dns->rdata);
    }

    cleanup_openssl();
    printf("END!!!");
    return 0;
}

void printRecords(dns_resource_record_t *answer, int count){
	int i;
	char ipv4[INET_ADDRSTRLEN], ipv6[INET6_ADDRSTRLEN];
	for (i = 0; i < count; i++){
		printRecord(&answer[i]);
	}
}

int sendQueryViaUDP(unsigned char *buf, int query_len, unsigned char *dest){
	int socket_desc, dest_len;
	struct sockaddr_in dest_addr;
	struct timeval timeout;

	socket_desc = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (socket_desc == -1){
		printf("Socket creation failed : %s...\n", strerror(errno));
		return -1;
	}

	// Set receive timeout
    timeout.tv_sec = 15;  // 5 second timeout
    timeout.tv_usec = 0;
    if (setsockopt(socket_desc, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("Error setting socket timeout");
		close(socket_desc);
		return -1;
    }

	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, dest, &dest_addr.sin_addr) <= 0) {
        printf("Invalid DNS resolver address: %s\n", dest);
		close(socket_desc);
		return -1;
    }

	dest_len = sizeof(dest_addr);

	if (sendto(socket_desc, (char *)buf, query_len, 0, (struct sockaddr *) &dest_addr, (socklen_t) dest_len) < 0)
	{
		perror("Error sending query");
		close(socket_desc);
		return -1;
	}
	printf("DNS query sent\n");

	if (recvfrom(socket_desc, (char *)buf, 65535, 0, (struct sockaddr *) &dest_addr, (socklen_t *) &dest_len) < 0){
		perror("Error receiving query response");
		close(socket_desc);
		return -1;
	}
	printf("DNS query response received successfully\n");
	return 0;
}

int sendQueryViaTCP(unsigned char *buf, int query_len, unsigned char *dest){
	int socket_desc, dest_len;
	struct sockaddr_in dest_addr;
	struct timeval timeout;

	socket_desc = socket(AF_INET, SOCK_STREAM, 0);
	if (socket_desc == -1){
		printf("Socket creation failed : %s...\n", strerror(errno));
		return -1;
	}

	// Set receive timeout
    timeout.tv_sec = 15;  // 15 second timeout
    timeout.tv_usec = 0;
    if (setsockopt(socket_desc, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("Error setting socket timeout");
		close(socket_desc);
		return -1;
    }

	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, dest, &dest_addr.sin_addr) <= 0) {
        printf("Invalid DNS resolver address: %s\n", dest);
		close(socket_desc);
		return -1;
    }
	dest_len = sizeof(dest_addr);

	if (connect(socket_desc, (struct sockaddr *) &dest_addr, (socklen_t) dest_len) < 0){
		perror("Failed to connect to the server");
		close(socket_desc);
		return -1;
	}

	if (send(socket_desc, (char *)buf, query_len, 0) < 0){
		perror("Failed to send query");
		close(socket_desc);
		return -1;
	}
	printf("DNS query sent successfully\n");

	if (recv(socket_desc, (char *)buf, 65536, 0) <= 0){
		perror("Failed to receive response");
		close(socket_desc);
		return -1;
	}
	printf("Query response received successfully\n");

	shutdown(socket_desc, SHUT_RDWR);
	close(socket_desc);
	return 0;
}

int sendQueryViaTLS(unsigned char *buf, int query_len, unsigned char *dest){
	int socket_desc, dest_len;
	struct sockaddr_in dest_addr;
	struct timeval timeout;
	SSL_CTX *ctx;
    SSL *ssl;

	socket_desc = socket(AF_INET, SOCK_STREAM, 0);
	if (socket_desc == -1){
		printf("Socket creation failed : %s...\n", strerror(errno));
		return -1;
	}

	// Set receive timeout
    timeout.tv_sec = 15;  // 15 second timeout
    timeout.tv_usec = 0;
    if (setsockopt(socket_desc, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("Error setting socket timeout");
		close(socket_desc);
		return -1;
    }

	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(853);
    if (inet_pton(AF_INET, dest, &dest_addr.sin_addr) <= 0) {
        printf("Invalid DNS resolver address: %s\n", dest);
		close(socket_desc);
		return -1;
    }
	dest_len = sizeof(dest_addr);

	if (connect(socket_desc, (struct sockaddr *) &dest_addr, (socklen_t) dest_len) < 0){
		perror("Failed to connect to the server");
		close(socket_desc);
		return -1;
	}

	ctx = create_context();
	ssl = SSL_new(ctx);
    SSL_set_fd(ssl, socket_desc);

	if (SSL_connect(ssl) <= 0){
		ERR_print_errors_fp(stderr);
		SSL_free(ssl);
		close(socket_desc);
		SSL_CTX_free(ctx);
		cleanup_openssl();
		return -1;
	}

	if (SSL_write(ssl, buf, query_len) <= 0){
		perror("Error while sending response");
		return -1;
	}
	printf("DNS query sent successfully vis TLS over TCP\n");

	if (SSL_read(ssl, buf, 65536) <= 0){
		ERR_print_errors_fp(stderr);
		SSL_free(ssl);
		close(socket_desc);
		SSL_CTX_free(ctx);
		cleanup_openssl();
		return -1;
	}
	printf("Query response received successfully via TLS over TCP\n");

	SSL_free(ssl);
	close(socket_desc);
	SSL_CTX_free(ctx);
	cleanup_openssl();
	return 0;
}

dns_resource_record_t* getHostByNameAndDest(unsigned char *host, int qtype, unsigned char *dest){
	unsigned char buf[65536], *qname, *reader, ipv4[INET_ADDRSTRLEN];
	dns_header_t *header;
	dns_query_info_t *qinfo;

	int i, j, gain, query_len = 0;

	dns_resource_record_t answer[16], auth[16], addit[16], *result = NULL;

	packDNSQuery(host, qtype, buf, &query_len, &header);

	if (sendQueryViaTLS(buf, query_len, dest) < 0){
		printf("Failed to receive response\n");
		goto resmark;
	}

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

	return result;
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