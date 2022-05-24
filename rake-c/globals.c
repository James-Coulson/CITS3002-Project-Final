// ---------------------- INCLUDES ---------------------- //

#include "rake-c.h"

// ---------------------- GLOBAL VARAIBLES ---------------------- //

// Defining packet types
int PKT_EXEC = 0;				// Execute command straight away and return response     					{ 'type': int, 'ack_num': int, 'files': int, 'cmd_length': int, 'command': str }
int PKT_CLOSE_CONN = 1;         // Issued to close the connection                        					{ 'type': int }
int PKT_ACK = 2;                // Issued to acknowledge previous sent packet            					{ 'type': int, 'ack_num': int }
int PKT_TERMINAL_OUTPUT = 3;    // Packet thats contents should be printed to terminal   					{ 'type': int, 'ack_num': int, 'files': int, 'output_length': int, 'output': str }
int PKT_FILE_DETAILS = 4;		// Contains the information about a file that is going to be transmitted	{ 'type': int, 'ack_num': int, 'filesize': int, 'filename': str }
								// After the ack for this packet is received it will transmit the file
int PKT_QUOTE_REQUEST = 5;		// Contains information about a quote wanted by the client					{ 'type': int, 'ack_num': int }
int PKT_QUOTE_RESPONSE = 6;		// Contains information about the requested quote							{ 'type': int, 'ack_num': int, 'quote': int }

// Defining structure to store actionsets
struct actionset actionsets[MAX_ACTIONSETS];

// Define verbose bool
bool verbose = false;

// Define local bool
bool local = false;

// Define port
int port = DEFAULT_PORT;
char *hosts[MAX_HOSTS];
