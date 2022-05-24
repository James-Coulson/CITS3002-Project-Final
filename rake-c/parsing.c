// ---------------------- INCLUDES ---------------------- //

#include "rake-c.h"

// ---------------------- PARSING FUNCTIONS ---------------------- //

int parse_port(char *buffer)	{
	// Gets the port from buffer
	//
	// Params;
	// - buffer: the buffer

	// Duping the buffer
	char *bufcopy = strdup(buffer);
	// Iterating through each word of the line then storing the last word
	char *word = strtok(bufcopy, " =");
	char *prevword;
	while (word != NULL)	{
		prevword = word;
		word = strtok(NULL, " =");
	}
	return atoi(prevword);
}

void parse_hosts(char *buffer) {
	// Gets hosts from buffer
	//
	// Params;
	//  - buffer: the buffer

	// Intialising token and skipping 'HOSTS ='
	char *token = strtok(buffer, " ");
	token = strtok(NULL, " ");
	token = strtok(NULL, " ");

	// Counter to store number of hosts
	int host_count = 0;

	// Iterate through buffer obtaining hosts
	while (token != NULL) {
		// Allocate memory for hosts
		hosts[host_count] = malloc(strlen(token) * sizeof(char));

		// Copy hosts
		strcpy(hosts[host_count], token);

		// Remove '\n' from end of string
		hosts[host_count][strcspn(hosts[host_count], "\n")] = '\0';

		// Increment counter and get next token
		host_count++;
		token = strtok(NULL, " ");
	}
}

bool parse_file(char *path) {
	// Used to parse a given file into the actionsets data-structure
	//
	// Params:
	//  - path: The relative pathname for the file
	//
	// Return:
	//  - Returns true if file is successfully parsed and false otherwise
	//
	// Assumptions:
	//  (*1) Assumes that entire line of file will fit in the buffer (treats each buffer as new line)
	//  (*2) Assumes comment "#" will only be at start of line

	// Create file pointer and buffer
	FILE *fptr;
	char buffer[2055];

	// Printing starting file parsing
	if (verbose) {
		printf("----------------- Parsing Rakefile ----------------\n\n");
		printf("path %s\n", path);
	}

	// Opening file
	if ((fptr = fopen(path, "r")) != NULL) {
		// Verbose
		if (verbose) { printf("\n\t\t*Printing Rakefile*\n\n"); }

		// Variables to track location in data-structure
		int actionset = -1;
		int command = -1;

		// Bool array to track if header has been parsed
		bool header_parsed[2] = {false, false};	// header_parsed[0] -> PORT parsed, header_parsed[1] -> HOSTS parsed

		// Break up while loop into two sections, one for parsing the header and a second for parsing the body of the Rakefiile
		// Read through file line by line adding to data-structure
		while (fgets(buffer, sizeof(buffer), fptr) != NULL) {		// (*1)
			// Printing line if verbose
			if (verbose) { printf("%s", buffer); }

			// Discarding comment line (*2)
			if (buffer[0] == '#') { continue; }

			// Discard empty line
			if (buffer[0] == '\n') { continue; }

			// If the PORT and HOSTS haven't been parsed we are still in the header
			if (header_parsed[0] == false || header_parsed[1] == false) {
				if (buffer[0] == 'P') {
					header_parsed[0] = true;

					// Get port number fromm the line
					port = parse_port(buffer);
				} else if (buffer[0] == 'H') {
					// Set hosts parsed to true
					header_parsed[1] = true;

					// Parse hosts
					parse_hosts(buffer);
				}
			} else {	// Parse actionsets
				// Counting number fo tabs
				int tab_count = 0;
				if (buffer[0] == '\t') {
					tab_count++;
					if (buffer[1] == '\t') {
						tab_count++;
					}
				}

				// Interpreting tab count
				if (tab_count == 0) { // New actionset
					// Incrementing actionset counter and resetting command counter
					actionset++;
					command = -1;

					// Giving actionset its number
					actionsets[actionset].actionset_num = actionset + 1;
					actionsets[actionset].used = true;

					// Printing output if vebose
					// if (verbose) { printf("actionset%i:\n", actionsets[actionset].actionset_num); }

				} else if (tab_count == 1) { // New command
					// Incrementing command counter
					command++;

					// Checking if command is remote and assigning str_offset
					int str_offset = 1;
					if (is_remote(buffer + 1)) {
						// If command is remote increase str_offset and label command as remote
						str_offset += 7;
						actionsets[actionset].commands[command].remote = true;
					}

					// removing '\n' from the end of command
					char *cmd = strtok(buffer + str_offset, "\n");

					// Allocating memory for command
					// actionsets[actionset].commands[command].cmd = malloc(sizeof(char) * strlen(cmd));

					// Copying command to data-structure
					strcpy(actionsets[actionset].commands[command].cmd, cmd);
					actionsets[actionset].commands[command].used = true;

					// Printing output if vebose
					// if (verbose) { printf("\n\t%s\n", actionsets[actionset].commands[command].cmd); }

				} else if (tab_count == 2) { // Parse required file
					// Defining file counter
					int file = 0;

					// Initialising strtok and skipping 'requires'
					char *token = strtok(buffer + 2, " ");
					token = strtok(NULL, " ");

					// Iterate through files required
					while (token != NULL) {
						// Allocating memory and setting file to token
						actionsets[actionset].commands[command].req_files[file] = malloc(sizeof(char) * strlen(token));
						strcpy(actionsets[actionset].commands[command].req_files[file], token);

						// Removing '\n' if specified in filename
						actionsets[actionset].commands[command].req_files[file][strcspn(actionsets[actionset].commands[command].req_files[file], "\n")] = '\0';

						// Getting next file and incrementing file counter
						token = strtok(NULL, " ");
						file++;
					}
				}
			}
		}

		if (verbose) { printf("\n\t\t*End Rakefile*\n"); }

		if (verbose) {
			printf("\nPrinting out parsed commands from data-structure\n");
			// Iterate through actionsets
			for (int i = 0; i < MAX_ACTIONSETS; i++) {
				// Skip actionset if it was not used
				if (!actionsets[i].used) { continue; }

				// Print current actionset
				printf("Actionset%i\n", i + 1);

				// Iterate through commands
				for (int j = 0; j < MAX_ACTIONSET_CMDS; j++) {
					// Skip command if it was not used
					if (!actionsets[i].commands[j].used) { continue; }
					printf("command: %s\n", actionsets[i].commands[j].cmd);

					for (int k = 0; k < MAX_FILES; k++) {
						if (actionsets[i].commands[j].req_files[k] == NULL) { break; }
						printf("    Required file: %s\n", actionsets[i].commands[j].req_files[k]);
					}
				}
			}
		}

		if (verbose) { printf("\n------------ Finished Parsing Rakefile ------------\n\n"); }

		return true;
	} else {
		// If file could not be opened successfully return false
		return false;
	}
}

bool bytes_to_packet(PACKET *pkt, char *source) {
	// Converts bytes received from server to a packet
	//
	// Params:
	//  source - The raw bytes to be converted to a packet
	//  pkt - The packet to convert bytes into
	//
	// Returns
	//  - true if succesffult conversion, false otherwise

	// Check that a complete packet had been given
	if (source[0] != '{' && source[strlen(source) - 1] != '}') {
		printf("An incomplete packet was given to be parsed: bytes=%s\n", source);
		return false;
	}

	char *string = source;

	if (verbose) { printf("Parsing %s to packet\n", source); }

	// Get packet type (move string to beginning of packet type)
	string += 6;
	int pkt_type = 0;

	// Converting characters to number
	while (*(string + 1) != ' ') {
		string++;
		pkt_type *= 10;
		pkt_type += atoi(string);
	}

	// Moving string to space (' ') after type
	string++;

	// Adding pkt_type to pkt
	pkt->pkt_type = pkt_type;

	// Print packet type if verbose
	if (verbose) { printf("Packet type = %i : %i\n", pkt_type, pkt->pkt_type); }

	// Parsing rest of packet depending on type (only need to parse packet types that the client will actually receive)
	if (pkt->pkt_type == PKT_ACK) {	// If type is PKT_ACK
		// Increment string to get to beginning of ack_num:
		string += 9;

		// Defining ack_num
		int ack_num = atoi(string);

		// Adding ack_num to pkt
		pkt->contents[0] = malloc(snprintf(NULL, 0, "%i", ack_num));
		sprintf(pkt->contents[0], "%i", ack_num);

		// Print ack_num if verbose
		if (verbose) { printf("Packet ack_num = %i : %s\n", ack_num, pkt->contents[0]); }
	} else if (pkt->pkt_type == PKT_TERMINAL_OUTPUT) {
		// -- Parsing ack_num --

		// Increment string to get the beginning of ack_num
		string += 9;

		// Defining ack_num
		int ack_num = atoi(string);

		// Adding ack_num to pkt
		pkt->contents[0] = malloc(snprintf(NULL, 0, "%i", ack_num));
		sprintf(pkt->contents[0], "%i", ack_num);

		// Print ack_num if verbose
		if (verbose) { printf("Packet ack_num = %i : %s\n", ack_num, pkt->contents[0]); }

		// -- Parsing files --

		// Moving string pointer to next blank space
		while (*(string + 1) != ' ') {
			string++;
		}

		// Increment string to beginning of files
		string += 8;

		// Convert string to int
		int files = atoi(string);

		// Adding files to pkt
		pkt->contents[1] = malloc(snprintf(NULL, 0, "%i", files));
		sprintf(pkt->contents[1], "%i", files);

		// Print files if verbose
		if (verbose) { printf("Packet files = %i : %s\n", files, pkt->contents[1]); }

		// -- Parsing output_length --

		// Moving string pointer to next blank space
		while (*(string + 1) != ' ') {
			string++;
		}

		// Increment to beginning of output_length
		string += 16;

		// Convert string to int
		int output_length = atoi(string);

		// Adding output_length to pkt
		pkt->contents[2] = malloc(snprintf(NULL, 0, "%i", output_length));
		sprintf(pkt->contents[2], "%i", output_length);

		// Print output_length if verbose
		if (verbose) { printf("Packet output_length = %i : %s\n", output_length, pkt->contents[2]); }

		// -- Parsing output --

		// Moving string pointer to next blank space
		while (*(string + 1) != ' ') {
			string++;
		}

		// Increment to beginning of output
		string += 9;

		// Copying output to package
		char *output = malloc(sizeof(char) * strlen(string));
		strcpy(output, string);

		// Inserting end of string before closing brackets '}'
		output[strlen(output) - 2] = '\0';

		// Converting binary to string
		pkt->contents[3] = malloc(strlen(output) * 8 + 1);
		if (!binary_to_string(pkt->contents[3], output)) {
			printf("!! Error converting binary to string. binary=%s\n", output);
			return false;
		}

		// Printing output if verbose
		if (verbose) { printf("output = %s\n", pkt->contents[3]); }
	} else if (pkt->pkt_type == PKT_FILE_DETAILS) {
		// -- Parsing ack_num --

		// Increment string to get the beginning of ack_num
		string += 9;

		// Defining ack_num
		int ack_num = atoi(string);

		// Adding ack_num to pkt
		pkt->contents[0] = malloc(snprintf(NULL, 0, "%i", ack_num));
		sprintf(pkt->contents[0], "%i", ack_num);

		// Print ack_num if verbose
		if (verbose) { printf("Packet ack_num = %i : %s\n", ack_num, pkt->contents[0]); }

		// -- Parsing filesize --

		// Moving string pointer to next blank space
		while (*(string + 1) != ' ') {
			string++;
		}

		// Increment string to beginning of files
		string += 11;

		// Convert string to int
		int filesize = atoi(string);

		// Adding files to pkt
		pkt->contents[1] = malloc(snprintf(NULL, 0, "%i", filesize));
		sprintf(pkt->contents[1], "%i", filesize);

		// Print files if verbose
		if (verbose) { printf("Packet filesize = %i : %s\n", filesize, pkt->contents[1]); }

		// -- Parsing filename --

		// Moving string pointer to next blank space
		while (*(string + 1) != ' ') {
			string++;
		}

		// Increment to beginning of output
		string += 11;

		// Copying output to package
		char *output = malloc(sizeof(char) * strlen(string));
		strcpy(output, string);

		// Inserting end of string before closing brackets '}'
		output[strlen(output) - 2] = '\0';

		// Converting binary to string
		pkt->contents[2] = malloc(strlen(output) * 8 + 1);
		if (!binary_to_string(pkt->contents[2], output)) {
			printf("!! Error converting binary to string. binary=%s\n", output);
			return false;
		}

		// Printing output if verbose
		if (verbose) { printf("filename = %s\n", pkt->contents[2]); }

	} else if (pkt->pkt_type == PKT_QUOTE_RESPONSE) {
		// -- Parsing ack_num --

		// Increment string to get the beginning of ack_num
		string += 9;

		// Defining ack_num
		int ack_num = atoi(string);

		// Adding ack_num to pkt
		pkt->contents[0] = malloc(snprintf(NULL, 0, "%i", ack_num));
		sprintf(pkt->contents[0], "%i", ack_num);

		// Print ack_num if verbose
		if (verbose) { printf("Packet ack_num = %i : %s\n", ack_num, pkt->contents[0]); }

		// -- Parsing quote --

		// Increment string to get to the beginning of quote
		string += 7;

		// Defining quote
		int quote = atoi(string);

		// Adding quote to pkt
		pkt->contents[1] = malloc(snprintf(NULL, 0, "%i", quote));
		sprintf(pkt->contents[1], "%i", quote);

		// Print quote if verbose
		if (verbose) { printf("Packet quote = %i : %s\n", quote, pkt->contents[1]); }

	} else {
		printf("!! Unknown packet tried to be parsed");
		return false;
	}

	return true;
}
