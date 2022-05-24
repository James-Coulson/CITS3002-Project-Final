#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <libgen.h>

// cc -std=c11 -Wall -Werror -o rake-c rake-c.c

// ---------------------- MACRO FUNCTIONS ----------------------

// Defining MIN function
#define MIN(a,b) (((a)<(b))?(a):(b))

// ---------------------- GLOBAL CONSTANTS ---------------------- //

// Defining program constants
#define MAX_ACTIONSET_CMDS 20
#define MAX_ACTIONSETS 20
#define MAX_HOSTS 20
#define MAX_FILES 20
#define DEFAULT_PORT 12345
#define MAX_COMMAND_LENGTH 1023
#define MAX_PKT_CONTENTS 20
#define MAX_RAND_NUM 99999
#define DEFAULT_FILE_BUFFER_SIZE 64	// Change this so that when a connection is first established the server specifies the buffer size

// ---------------------- PACKET TYPES ---------------------- //

// Defining packet types
extern int PKT_EXEC;				// Execute command straight away and return response     					{ 'type': int, 'ack_num': int, 'files': int, 'cmd_length': int, 'command': str }
extern int PKT_CLOSE_CONN;         	// Issued to close the connection                        					{ 'type': int }
extern int PKT_ACK;                	// Issued to acknowledge previous sent packet            					{ 'type': int, 'ack_num': int }
extern int PKT_TERMINAL_OUTPUT;    	// Packet thats contents should be printed to terminal   					{ 'type': int, 'ack_num': int, 'files': int, 'output_length': int, 'output': str }
extern int PKT_FILE_DETAILS;		// Contains the information about a file that is going to be transmitted	{ 'type': int, 'ack_num': int, 'filesize': int, 'filename': str }
									// After the ack for this packet is received it will transmit the file
extern int PKT_QUOTE_REQUEST;		// Contains information about a quote wanted by the client					{ 'type': int, 'ack_num': int }
extern int PKT_QUOTE_RESPONSE;		// Contains information about the requested quote							{ 'type': int, 'ack_num': int, 'quote': int }

// ---------------------- STRUCTURES ---------------------- //

// Defining packet structure
typedef struct {
	int pkt_type;
	char *contents[MAX_PKT_CONTENTS];
} PACKET;

// Defining structure to store command
struct cmd {
	char cmd[MAX_COMMAND_LENGTH];
	bool used;
	bool remote;
	char *req_files[MAX_FILES];
} CMD;

// Defining structure to store actionset
struct actionset {
	int actionset_num;
	bool used;
	struct cmd commands[MAX_ACTIONSET_CMDS];
} ACTIONSET;

// ---------------------- ACTIONSETS ---------------------- //

// Defining structure to store actionsets
extern struct actionset actionsets[];

// ---------------------- GLOBAL VARIABLES ---------------------- //

// Define verbose bool
extern bool verbose;

// Define local bool
extern bool local;

// Define port
extern int port;
extern char *hosts[];

// ---------------------- UTILITY FUNCTIONS ---------------------- //

// Defining is_remote function
extern bool is_remote(const char* cmd);

// Defining count_occurences function
extern int count_occurences(char *string, char c);

// Defining string_to_binary function
extern bool string_to_binary(char *dest, char *source);

// Defining rand_int function
extern int rand_int(int lower, int upper);

// Defining binary_to_string function
extern bool binary_to_string(char *dest, char *source);

// ---------------------- PARSING FUNCTIONS ---------------------- //

// Defining parse_port function
extern int parse_port(char *buffer);

// Defining parse_hosts function
extern void parse_hosts(char *buffer);

// Defining parse_file function
extern bool parse_file(char *path);

// Defining bytes_to_packet function
extern bool bytes_to_packet(PACKET *pkt, char *source);

// ---------------------- FILE TRANSMITTING FUNCTIONS ---------------------- //

// Defining send_file function
extern void send_file(FILE *fp, int sockfd);

// Defining read_data function
extern bool read_data(int sockfd, void *buf, int buflen);

// Defining receive_file function
extern bool receive_file(FILE *fp, int sockfd, int fsize);

// ---------------------- QUOTING FUNCTIONS ---------------------- //

// Defining get_quote function
extern int get_quote(int host);

// Defining quote_hosts function
extern int quote_hosts();

// ---------------------- EXECUTING FUNCTIONS ---------------------- //

// Defining execute_locally function
extern bool execute_locally();

// Defining execute function
extern bool execute();
