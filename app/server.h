#include <stdlib.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define QR_MASK 	0x8000
#define OPCODE_MASK 0x7800
#define AA_MASK 	0x0400
#define TC_MASK 	0x0200
#define RD_MASK 	0x0100
#define RA_MASK 	0x0080
#define Z_MASK 		0x0070
#define RCODE_MASK 	0x000F

#define A_MASK 		0x01
#define NS_MASK 	0x02
#define CNAME_MASK 	0x05
#define AAAA_MASK 	0x1c

#define BUF_SIZE 8192
#define QUEUE_SIZE 4
#define THREAD_POOL_SIZE 20

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
	unsigned char *qname;
	dns_query_info_t *qinfo;
} dns_query_t;

typedef struct __attribute__((packed)){
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t rdlength; 
} dns_resource_data_t;

typedef struct{
	unsigned char *name;
	dns_resource_data_t *resource;
	unsigned char *rdata;
} dns_resource_record_t;

typedef struct {
	int conn_type;
	int client_id;
	int socket_desc;
	SSL *ssl;
	unsigned char buf[BUF_SIZE];
	struct sockaddr_in client_addr;
	int client_addr_len;
	int bytes_read;
} client_request_t;

typedef struct {
	client_request_t *requests[QUEUE_SIZE];
	int head, tail, size;
	pthread_mutex_t mutex;
	pthread_cond_t isNotFull;
	pthread_cond_t isNotEmpty;
} task_queue_t;

dns_resource_record_t* getHostByName(unsigned char* host, int qtype);

dns_resource_record_t* getHostByNameAndDest(unsigned char *host, int qtype, unsigned char *dest);

void changeToDNSNameFormat(unsigned char *dns, unsigned char *host);

void getDNSresolvers();

unsigned char* readNameFromDNSFormat(unsigned char *reader, unsigned char *buf, int *gain);

void packDNSQuery(unsigned char *host, int qtype, unsigned char *buf, int *query_len, dns_header_t **header);

void unpackDNSResponse(unsigned char *buf, dns_resource_record_t *answer, dns_resource_record_t *auth, 
	dns_resource_record_t *addit, dns_header_t **header);

void printRecords(dns_resource_record_t *answer, int count);

void printRecord(dns_resource_record_t *answer);

dns_resource_record_t* getHostFromResolver(unsigned char *host, int qtype);

void init_queue(task_queue_t *tasks);

void enqueue_task(task_queue_t *tasks, client_request_t *client);

client_request_t* dequeue_task(task_queue_t *tasks);

void *worker_thread(void *arg);