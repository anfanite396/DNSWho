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
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "server.h"

#define UNENCRYPT_PORT 2053
#define ENCRYPT_PORT 853

void handleUDPConnection(int udp_socket, client_request_t *client);
void handleTCPConnection(int tcp_socket, client_request_t *client);
void handleTLSConnection(int tls_socket, client_request_t *client, SSL_CTX *ctx);
void init_openssl();
void cleanup_openssl();
SSL_CTX* createAndConfigureContext();

unsigned char dns_resolvers[10][256];
unsigned char root_servers[13][256];

task_queue_t tasks;

int main() {
	// Disable output buffering
	setbuf(stdout, NULL);
 	setbuf(stderr, NULL);

	// Start Logging the outputs
    printf("Logs from this program will appear here!\n");

	// Get the names of standard DNS resolvers and Root name servers
	getDNSresolvers();

	// Initialize task queue
	init_queue(&tasks);

	// Init variables
	int udp_socket, tcp_socket, tls_socket, max_fd = 0, reuse = 1;
	struct sockaddr_in serv_addr_unenc, serv_addr_enc;
	pthread_t thread_pool[THREAD_POOL_SIZE];
	fd_set read_fd;
	SSL_CTX *ctx;

	// unsigned char host[256];
	// strcpy((char *)host, "codecrafters.io");
	// int qtype = 1;
	// dns_resource_record_t *dns = getHostByName(host, qtype);
	// if (dns != NULL)
	// 	printf("The IP address of %s is : %s\n", host, dns->rdata);

	// Creating a UDP socket
	udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
	if (udp_socket == -1){
		printf("Socket creation failed : %s...\n", strerror(errno));
		return 1;
	}

	if (setsockopt(udp_socket, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0){
		printf("SO_REUSEPORT failed: %s...\n", strerror(errno));
		return 1;
	}

	// Creating a TCP socket
	tcp_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (tcp_socket == -1){
		printf("Socket creation failed : %s...\n", strerror(errno));
		return 1;
	}

	if (setsockopt(tcp_socket, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0){
		perror("SO_REUSEPORT failed for TCP socket");
		return 1;
	}

	// Creating a TCP socket for accepting TLS connections
	tls_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (tls_socket == -1){
		printf("Socket creation failed : %s...\n", strerror(errno));
		return 1;
	}

	if (setsockopt(tls_socket, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0){
		perror("SO_REUSEPORT failed for TCP socket");
		return 1;
	}

	// Setting up the encrypted and unencrpyted servers
	serv_addr_unenc.sin_family = AF_INET;
	serv_addr_unenc.sin_port = htons(UNENCRYPT_PORT);
	serv_addr_unenc.sin_addr.s_addr = htonl(INADDR_ANY);

	serv_addr_enc.sin_family = AF_INET;
	serv_addr_enc.sin_port = htons(ENCRYPT_PORT);
	serv_addr_enc.sin_addr.s_addr = htonl(INADDR_ANY);

	// Bind the TCP and UDP socket to the address
	if (bind(udp_socket, (struct sockaddr *) &serv_addr_unenc, (socklen_t) sizeof(serv_addr_unenc)) != 0){
		perror("Bind failed with udp socket");
		return 1;
	}

	if (bind(tcp_socket, (struct sockaddr *) &serv_addr_unenc, (socklen_t) sizeof(serv_addr_unenc)) != 0){
		perror("Bind failed with tcp socket");
		return 1;
	}

	if (bind(tls_socket, (struct sockaddr *) &serv_addr_enc, (socklen_t) sizeof(serv_addr_enc)) != 0){
		perror("Bind failed with tls socket");
		return 1;
	}

	if (listen(tcp_socket, 4) < 0){
		perror("Failed to listen on TCP socket");
		exit(EXIT_FAILURE);
	}
	listen(tls_socket, 1);

	// Initiate the threads
	for (int i = 0; i < THREAD_POOL_SIZE; i++){
		pthread_create(&thread_pool[i], NULL, worker_thread, NULL);
	}

	// Set the max fd
	max_fd = (udp_socket > tcp_socket) ? udp_socket : tcp_socket;
	max_fd = (max_fd > tls_socket) ? max_fd : tls_socket;

	// Initialize OpenSSL
	init_openssl();
	ctx = createAndConfigureContext();

	while(1){
		FD_ZERO(&read_fd);
		FD_SET(udp_socket, &read_fd);
		FD_SET(tcp_socket, &read_fd);
		FD_SET(tls_socket, &read_fd);

		client_request_t *client = malloc(sizeof(client_request_t));
		if (client == NULL){
			perror("Failed to allocate memory");
			continue;
		}

		if (select(max_fd + 1, &read_fd, NULL, NULL, NULL) < 0){
			perror("Select error");
			exit(EXIT_FAILURE);
		}

		if (FD_ISSET(udp_socket, &read_fd)){
			handleUDPConnection(udp_socket, client);
		}

		if (FD_ISSET(tcp_socket, &read_fd)){
			handleTCPConnection(tcp_socket, client);
		}

		if (FD_ISSET(tls_socket, &read_fd)){
			handleTLSConnection(tls_socket, client, ctx);
		}
	}

	close(udp_socket);
	close(tcp_socket);
	close(tls_socket);
	SSL_CTX_free(ctx);
	cleanup_openssl();
	return 0;
}

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

void handleUDPConnection(int udp_socket, client_request_t *client){
	client->socket_desc = udp_socket;
	client->conn_type = 1;
	client->client_addr_len = sizeof(client->client_addr);
	client->bytes_read = recvfrom(udp_socket, client->buf, BUF_SIZE, 0, (struct sockaddr *) &(client->client_addr),
			(socklen_t *) &(client->client_addr_len));
	if (client->bytes_read == -1){
		perror("Error receiving data");
		return;
	}

	enqueue_task(&tasks, client);
}

void handleTCPConnection(int tcp_socket, client_request_t *client){
	int conn;

	client->conn_type = 2;
	client->client_addr_len = sizeof(client->client_addr);

	conn = accept(tcp_socket, (struct sockaddr *) &client->client_addr, (socklen_t *) &client->client_addr_len);
	if (conn < 0){
		printf("Unable to accept connection on port %d\n", UNENCRYPT_PORT);
		return;
	}
	printf("TCP connection established\n");

	client->socket_desc = conn;
	client->bytes_read = recv(conn, &client->buf, BUF_SIZE, 0);
	if (client->bytes_read <= 0){
		perror("Error receiving TCP data");
		close(conn);
		return;
	}

	enqueue_task(&tasks, client);
}

void handleTLSConnection(int tls_socket, client_request_t *client, SSL_CTX *ctx){
	int conn;

	client->conn_type = 3;
	client->client_addr_len = sizeof(client->client_addr);

	conn = accept(tls_socket, (struct sockaddr *) &client->client_addr, (socklen_t *) &client->client_addr_len);
	if (conn < 0){
		printf("Unable to accept connections on port %d\n", ENCRYPT_PORT);
		return;
	}
	printf("TLS connection established\n");

	client->socket_desc = conn;
	client->ssl = SSL_new(ctx);
	SSL_set_fd(client->ssl, conn);

	if (SSL_accept(client->ssl) <= 0){
		ERR_print_errors_fp(stderr);
        close(conn);
        SSL_free(client->ssl);
        return;
	}

	client->bytes_read = SSL_read(client->ssl, &client->buf, BUF_SIZE);
	if (client->bytes_read <= 0){
		perror("Error reading TLS data");
	}

	enqueue_task(&tasks, client);
}

SSL_CTX* createAndConfigureContext(){
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	method = TLS_server_method();
	ctx = SSL_CTX_new(method);
	if (!ctx){
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	// Set the key and cert
	if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0){
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0){
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	return ctx;
}

void init_queue(task_queue_t *tasks){
	tasks->head = tasks->tail = tasks->size = 0;
	pthread_mutex_init(&tasks->mutex, NULL);
	pthread_cond_init(&tasks->isNotFull, NULL);
	pthread_cond_init(&tasks->isNotEmpty, NULL);
}

void enqueue_task(task_queue_t *tasks, client_request_t *client){
	pthread_mutex_lock(&tasks->mutex);
	while(tasks->size == QUEUE_SIZE){
		pthread_cond_wait(&tasks->isNotFull, &tasks->mutex);
	}
	tasks->requests[tasks->tail] = client;
	tasks->tail = (tasks->tail + 1) % QUEUE_SIZE;
	tasks->size++ ;
	pthread_cond_signal(&tasks->isNotEmpty);
	pthread_mutex_unlock(&tasks->mutex);
}

client_request_t* dequeue_task(task_queue_t *tasks){
	pthread_mutex_lock(&tasks->mutex);
	while(tasks->size == 0){
		pthread_cond_wait(&tasks->isNotEmpty, &tasks->mutex);
	}
	client_request_t *client = tasks->requests[tasks->head];
	client->client_id = tasks->head;
	tasks->head = (tasks->head + 1) % QUEUE_SIZE;
	tasks->size-- ;
	pthread_cond_signal(&tasks->isNotFull);
	pthread_mutex_unlock(&tasks->mutex);
	return client;
}

void *worker_thread(void *arg){
	unsigned char *qname, *reader;
	dns_query_info_t *qinfo;
	int gain = 0;

	while(1){
		client_request_t *client = dequeue_task(&tasks);
		printf("Handling request from %s::%d\n", inet_ntoa(client->client_addr.sin_addr), ntohs(client->client_addr.sin_port));

		client->buf[client->bytes_read] = '\0';
		printf("Received %d bytes at thread %d\n", client->bytes_read, client->client_id);

		dns_header_t *header = (dns_header_t *) &client->buf;
		qname = (unsigned char *) &client->buf[sizeof(dns_header_t)];
		qinfo = (dns_query_info_t *) &client->buf[sizeof(dns_header_t) + strlen(qname) + 1];
		int size = sizeof(dns_header_t) + strlen(qname) + 1 + sizeof(dns_query_info_t);

		reader = readNameFromDNSFormat(qname, client->buf, &gain);

		dns_resource_record_t *result = getHostByName(reader, ntohs(qinfo->type));

		if (result == NULL){
			// Hum pe to hai hi na, ask someone else
			result = getHostFromResolver(qname, ntohs(qinfo->type));
			printf("Resorted to standard DNS resolvers\n");
		}

		if (result == NULL){
			// If no one has it, then probably the domain itself if not valid
			header->flags = 0;
			header->flags |= 3; 	// Non-existent domain
			header->flags |= QR_MASK;
			header->flags |= RA_MASK;
			header->flags = htons(header->flags);

			header->qcount = 0;
			header->ancount = 0;
			header->nscount = 0;
			header->arcount = 0;
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

			reader = (unsigned char *) &client->buf[size];
			memcpy(reader, qname, strlen(qname) + 1);
			size += strlen(qname) + 1;

			reader += strlen(qname) + 1;
			memcpy(reader, result->resource, sizeof(dns_resource_data_t));
			size += sizeof(dns_resource_data_t);

			reader += sizeof(dns_resource_data_t);
			inet_pton(AF_INET, result->rdata, reader);
			size += INET_ADDRSTRLEN;
		}

		// Send the response back
		if (client->conn_type == 1){
			if (sendto(client->socket_desc, &client->buf, size, 0, (struct sockaddr *) & client->client_addr, client->client_addr_len) == -1){
				perror("Error sending response");
			}
			else{
				printf("Query response sent successfully\n");
			}
		}
		else if (client->conn_type == 2){
			if (send(client->socket_desc, &client->buf, size, 0) < 0){
				perror("Error sending response");
			}
			else{
				printf("Query response sent successfully\n");
			}
			shutdown(client->socket_desc, SHUT_RDWR);
			close(client->socket_desc);
		}
		else if (client->conn_type == 3){
			if (SSL_write(client->ssl, &client->buf, size) <= 0){
				perror("Error sending response");
			}
			else{
				printf("Query response sent successfully\n");
			}
			SSL_shutdown(client->ssl);
			SSL_free(client->ssl);
			close(client->socket_desc);
		}

		free(result);
		free(client);
	}
	return NULL;
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

	// printf("The response is as follows....");
	// printf(" %d questions", ntohs((*header)->qcount));
	// printf(" %d answers", ntohs((*header)->ancount));
	// printf(" %d Authoritative servers", ntohs((*header)->nscount));
	// printf(" %d additional records\n", ntohs((*header)->arcount));

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
		else if (ntohs(auth[i].resource->type) == NS_MASK){
			auth[i].rdata = readNameFromDNSFormat(reader, buf, &gain);
			reader += gain;
		}
		else{
			// Ignore
			reader += ntohs(auth[i].resource->rdlength);
			auth[i].rdata = NULL;
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
	else if (ntohs(answer->resource->type) == NS_MASK){
		printf("%s\n", answer->rdata);
	}
	else{
		// Ignore
		printf("Ignored\n");
	}
}

void printRecords(dns_resource_record_t *answer, int count){
	int i;
	for (i = 0; i < count; i++){
		printRecord(&answer[i]);
	}
}

dns_resource_record_t* getHostByNameAndDest(unsigned char *host, int qtype, unsigned char *dest){
	// printf("Querying %s for %s\n", dest, host);
	unsigned char buf[BUF_SIZE], ipv4[INET_ADDRSTRLEN];
	dns_header_t *header;

	int socket_desc, i, j, dest_len, query_len = 0;
	struct sockaddr_in dest_addr;
	struct timeval timeout;

	dns_resource_record_t answer[20], auth[20], addit[20], *result = NULL;

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
        printf("Invalid DNS resolver address: %s\n", dest);
		goto resmark;
    }

	dest_len = sizeof(dest_addr);

	packDNSQuery(host, qtype, buf, &query_len, &header);

	if (sendto(socket_desc, (char *)buf, query_len, 0, (struct sockaddr *) &dest_addr, (socklen_t) dest_len) < 0)
	{
		perror("Error sending query");
		goto resmark;
	}
	// printf("DNS query sent\n");

	if (recvfrom(socket_desc, (char *)buf, 65535, 0, (struct sockaddr *) &dest_addr, (socklen_t *) &dest_len) < 0){
		perror("Error receiving query response");
		goto resmark;
	}
	// printf("DNS query response received successfully\n");

	unpackDNSResponse(buf, answer, auth, addit, &header);

	// printRecords(answer, ntohs(header->ancount));
	// printRecords(auth, ntohs(header->nscount));
	// printRecords(addit, ntohs(header->arcount));

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
		else if (ntohs(answer[i].resource->type) == CNAME_MASK){
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
			int gotIP = 0;
			for (j = 0; j < ntohs(header->arcount); j++){
				if (ntohs(addit[j].resource->type) == A_MASK && strcmp(addit[j].name, auth[i].rdata) == 0){
					if (inet_ntop(AF_INET, addit[j].rdata, (char *) ipv4, INET_ADDRSTRLEN) == NULL) {
						perror("Address conversion failed");
						continue;
					}

					result = getHostByNameAndDest(host, qtype, (unsigned char *) ipv4);
					if (result != NULL)
						goto resmark;
				}
			}

			if (!gotIP){
				dns_resource_record_t *record = getHostByName(auth[i].rdata, 1);
				if (record != NULL){
					result = getHostByNameAndDest(host, qtype, record->rdata);
					if (result != NULL)
						goto resmark;
				}
			}
		}
	}

resmark:
	for (i = 0; i < ntohs(header->ancount); i++){
		free(answer[i].name);
		free(answer[i].rdata);
	}

	for (i = 0; i < ntohs(header->nscount); i++){
		free(auth[i].name);
		free(auth[i].rdata);
	}

	for (i = 0; i < ntohs(header->arcount); i++){
		free(addit[i].name);
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
	for (i = 0; i < (int)strlen((char *) name);){
		ptr = name[i];
		for (j = i; j < i + ptr; j++){
			name[j] = name[j + 1];
		}
		name[i + ptr] = '.';
		i += ptr + 1;
	}
	name[i - 1] = '\0';		// Remove the last '.'

	return name;
}

void getDNSresolvers(){
	strcpy((char *) dns_resolvers[0], "1.1.1.1");
	strcpy((char *) dns_resolvers[1], "8.8.8.8");

	strcpy((char *) root_servers[0], "198.41.0.4");
	strcpy((char *) root_servers[1], "170.247.170.2");
	strcpy((char *) root_servers[2], "192.33.4.12");
	strcpy((char *) root_servers[3], "199.7.91.13");
	strcpy((char *) root_servers[4], "192.203.230.10");
	strcpy((char *) root_servers[5], "192.5.5.241");
	strcpy((char *) root_servers[6], "192.112.36.4");
	strcpy((char *) root_servers[7], "198.97.190.53");
	strcpy((char *) root_servers[8], "192.36.148.17");
	strcpy((char *) root_servers[9], "192.58.128.30");
	strcpy((char *) root_servers[10], "193.0.14.129");
	strcpy((char *) root_servers[11], "199.7.83.42");
	strcpy((char *) root_servers[12], "202.12.27.33");
}

void changeToDNSNameFormat(unsigned char* dns, unsigned char* host){
	int i = 0, j = 0;
	strcat((char*)host, ".");

	for (i = 0; i < (int)strlen((char*)host); i++){
		if (host[i] == '.'){
			*dns++ = i - j;
			for (; j < i; j++){
				*dns++ = host[j];
			}
			j++ ;
		}
	}
	host[strlen((char*)host) - 1] = '\0';
	*dns++ = '\0';
}