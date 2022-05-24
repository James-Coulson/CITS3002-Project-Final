// ---------------------- INCLUDES ---------------------- //

#include "rake-c.h"

// ---------------------- EXECUTING FUNCTIONS ---------------------- //

bool execute_locally() {
	// Used to execute commands/actionsets locally irrespective of if they have been defined as remote.
	//
	// Returns:
	//  - If execute was successful returns true, otherwise returns false.

	// Printing begining executing
	if (verbose) { printf("----------------- Executing Actionsets Locally ----------------\n\n"); }

	// Iterate through actionsets
	for (int i = 0; i < MAX_ACTIONSETS; i++) {
		// Skip actionset if it was not used
		if (!actionsets[i].used) { continue; }

		// Obtain current actionset
		struct actionset current_actionset = actionsets[i];

		// Print current actionset to terminal
		if (verbose) { printf("Current actionset number = %i\n", current_actionset.actionset_num); }

		// Iterate through commands
		for (int j = 0; j < MAX_ACTIONSET_CMDS; j++) {
			// Skip command if it is not used
			if (!current_actionset.commands[j].used) { continue; }

			// Obtain current command
			struct cmd current_cmd = current_actionset.commands[j];

			// Print current command to terminal
			if (verbose) { printf("\nExecuting command: %s\n", current_cmd.cmd); }

			// Exec command locally
			system(current_cmd.cmd);
		}

		// Printing new line
		printf("\n");
	}

	return true;
}

bool execute() {
	// Used to send commands to different servers and handle output/file from the servers
	//
	// Return:
	//  - true if successfull, false otherwise
	//
	// Assumptions:
	//  (*1) Assumes that there is only one server connection
	//
	// TODO:
	//  - Implement ack/nack acceptance after packet transmission

	// Printing begining executing
	if (verbose) { printf("----------------- Executing Actionsets ----------------\n\n"); }

	// Iterate through actionsets
	for (int i = 0; i < MAX_ACTIONSETS; i++) {
		// Skip actionset if it was not used
		if (!actionsets[i].used) { break; }

		// Obtain current actionset
		struct actionset current_actionset = actionsets[i];

		// Print current actionset to terminal
		if (verbose) { printf("Current actionset number = %i\n", current_actionset.actionset_num); }

		// Iterate through commands
		for (int j = 0; j < MAX_ACTIONSET_CMDS; j++) {
			// Skip command if it is not used
			if (!current_actionset.commands[j].used) { break; }

			// Get preferred host
			int host_used;
			if (current_actionset.commands[j].remote == true) {
				host_used = quote_hosts();
			} else {
				host_used = -1;
			}

			// Fork here
			if (fork() != 0) { continue; }

			// Creating Socket and buffer
			int sockfd = 0;
			int n = 0;
			struct sockaddr_in serv_addr;
			char recvBuff[8192];

			memset(recvBuff, '0', sizeof(recvBuff));
			if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
				printf("\n Error : Could not create socket \n");
				exit(EXIT_FAILURE);
			}

			serv_addr.sin_family = AF_INET;

			if (host_used != -1) {
				if (count_occurences(hosts[host_used], ':') == 1) {
					char *host_str = strdup(hosts[host_used]);
					strtok(host_str, ":");
					int pott = atoi(strtok(NULL, ":"));
					host_str = strdup(hosts[host_used]);
					serv_addr.sin_port = htons(pott);
					serv_addr.sin_addr.s_addr = inet_addr(strtok(host_str, ":"));
				} else {
					serv_addr.sin_port = htons(port);
					serv_addr.sin_addr.s_addr = inet_addr(hosts[host_used]);
				}
			} else {
				serv_addr.sin_port = htons(port);
				serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
			}

			// Connecting to server
			if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr))<0) {
				printf("\n Error : Connect Failed  - %u : %i\n", serv_addr.sin_addr.s_addr, port);
				return -1;
			}

			// Obtain current command
			struct cmd current_cmd = current_actionset.commands[j];

			//  -- Creating packet --

			// Getting varaibles to put in packet
			int cmd_len = strlen(current_cmd.cmd) * sizeof(char);
			int cmd_type = PKT_EXEC;

			// Counting number of files needed
			int cmd_files = 0;
			for (int k = 0; k < MAX_FILES; k++) {
				if (current_cmd.req_files[k] != NULL) { cmd_files++; }
				else { break; }
			}

			// Printing number of files required
			if (verbose) { printf("Number of files for command: num_files=%i\n", cmd_files); }

			// Converting commmand to binary
			char *cmds = malloc(strlen(current_cmd.cmd) * 8 + 1);
			string_to_binary(cmds, current_cmd.cmd);

			// Print binary command if verbose
			if (verbose) { printf("Binary cmd: %s\n", cmds); }

			// Allocating memory for packet
			int ack_num = rand_int(0, MAX_RAND_NUM);
			size_t mem_needed = snprintf(NULL, 0, "{ type:%i ack_num:%i files:%i cmd_len:%i cmd:%s }", cmd_type, ack_num, cmd_files, cmd_len, cmds);
			char *packet = malloc(mem_needed);
			sprintf(packet, "{ type:%i ack_num:%i files:%i cmd_len:%i cmd:%s }", cmd_type, ack_num, cmd_files, cmd_len, cmds);

			// Print current command to terminal and packet
			if (verbose) { printf("Made packet: %s\n", packet); }
			if (verbose) { printf("\nExecuting command: %s\n", current_cmd.cmd); }

			// Sleep thread waiting for server to catch up
			sleep(2);

			// Sending packet to server
			if (send(sockfd, packet, sizeof(char) * strlen(packet), 0) < 0) {
				printf("Send failed");
				return 1;
			}

			// Printing sent if verbose
			if (verbose) { printf("sent\n"); }

			//  -- Waiting for acknowledgement --
			if (verbose) { printf("Waiting for ack\n"); }

			// Waiting for ack
			while((n = read(sockfd, recvBuff, sizeof(recvBuff)-1)) > 0) {
				recvBuff[n] = 0;

				// Printing bytes if verbose
				if (verbose) { printf("Packet received, %s\n", recvBuff); }

				// Define packet and parse bytes to packet
				PACKET pkt;
				bytes_to_packet(&pkt, recvBuff);

				// If packet is ACK break
				if (pkt.pkt_type == PKT_ACK && atoi(pkt.contents[0]) == ack_num) {
					if (verbose) { printf("Received ack for ack number = %s\n", pkt.contents[0]); }
					break;
				}
			}

			// If there are files required to be transmitted
			if (cmd_files > 0) {
				// Make PKT_FILE_DETAILS packet
				for (int k = 0; k < cmd_files; k++) {
					// Get file needing to be transmitted
					char *file = current_cmd.req_files[k];

					// -- Creating PKT_FILE_DETAILS --
					FILE *fp;
					if ((fp = fopen(file, "rb")) == NULL) {
						printf("!!!!! Error opening file !!!!, path=%s\n", file);
					}

					// Creating stat buffer
					struct stat *buff = malloc(sizeof(struct stat));

					// Get file into stat buffer
					stat(file, buff);

					// Getting file size
					off_t file_size = buff->st_size;
					char *filename = basename(file);

					// Printing file details if verbose
					if (verbose) { printf("Filename: %s\nFile size: %lld\n", filename, file_size); }

					// Getting packet details
					ack_num = rand_int(0, MAX_RAND_NUM);
					char *binary_filename = malloc(strlen(filename) * 8 + 1);
					string_to_binary(binary_filename, filename);

					// Making packet
					char *file_details_pkt = malloc(snprintf(NULL, 0, "{ type:%i ack_num:%i filesize:%lld filename:%s }", PKT_FILE_DETAILS, ack_num, file_size, binary_filename));
					sprintf(file_details_pkt, "{ type:%i ack_num:%i filesize:%lld filename:%s }", PKT_FILE_DETAILS, ack_num, file_size, binary_filename);

					// Print packet made if verbose
					if (verbose) { printf("Made packet %s\n", file_details_pkt); }

					// Sending packet to server
					if (send(sockfd, file_details_pkt, sizeof(char) * strlen(file_details_pkt), 0) < 0) {
						printf("Send failed");
						exit(EXIT_FAILURE);
					}

					// Waiting for ack
					while((n = read(sockfd, recvBuff, sizeof(recvBuff)-1)) > 0) {
						recvBuff[n] = 0;

						// Printing bytes if verbose
						if (verbose) { printf("Packet received, %s\n", recvBuff); }

						// Define packet and parse bytes to packet
						PACKET pkt;
						bytes_to_packet(&pkt, recvBuff);

						// If packet is ACK break
						if (pkt.pkt_type == PKT_ACK && atoi(pkt.contents[0]) == ack_num) {
							if (verbose) { printf("Received ack for ack number = %s\n", pkt.contents[0]); }
							break;
						}
					}

					// Sending file
					send_file(fp, sockfd);

					// Waiting for ack
					while((n = read(sockfd, recvBuff, sizeof(recvBuff)-1)) > 0) {
						recvBuff[n] = 0;

						// Printing bytes if verbose
						if (verbose) { printf("Packet received, %s\n", recvBuff); }

						// Define packet and parse bytes to packet
						PACKET pkt;
						bytes_to_packet(&pkt, recvBuff);

						// If packet is ACK break
						if (pkt.pkt_type == PKT_ACK && atoi(pkt.contents[0]) == ack_num) {
							if (verbose) { printf("Received ack for ack number = %s\n", pkt.contents[0]); }
							break;
						}
					}

					sleep(3);
				}
			}

			// Define pkt
			PACKET pkt;

			// Getting response from socket
			while((n = read(sockfd, recvBuff, sizeof(recvBuff)-1)) > 0) {
				recvBuff[n] = 0;

				// Printing bytes if verbose
				if (verbose) { printf("Packet received, %s\n", recvBuff); }

				// Parse bytes to packet
				if (!bytes_to_packet(&pkt, recvBuff)) {
					printf("!! Error converting received bytes to packet. bytes=%s\n", recvBuff);
					exit(EXIT_FAILURE);
				}
				// Break when packet received
				if (strlen(recvBuff) > 0) {
					break;
				}
			}

			// If packet is terminal output print output to terminal
			if (pkt.pkt_type == PKT_TERMINAL_OUTPUT) {
				// Print terminal output
				printf("%s\n", pkt.contents[3]);

				// Create ack packet
				char *ack_packet = malloc(snprintf(NULL, 0, "{ type:%i ack_num:%s }", PKT_ACK, pkt.contents[0]));
				sprintf(ack_packet, "{ type:%i ack_num:%s }", PKT_ACK, pkt.contents[0]);

				// Get number of files
				int files_num = atoi(pkt.contents[1]);

				// Sending ack
				if (verbose) { printf("Sending ack. ack=%s\n", ack_packet); }
				if (send(sockfd, ack_packet, sizeof(char) * strlen(ack_packet), 0) < 0) {
					printf("Send failed");
					exit(EXIT_FAILURE);
				}

				// Print number of files if verbose
				if (verbose) { printf("Receiving %i files from server\n", files_num); }

				// If files need to be received
				if (files_num > 0) {
					// Define counter and repeat for each file
					int files_received = 0;
					while (files_received <  files_num) {
						PACKET file_details;
						// Getting initial PKT_FILE_DETAILS
						while((n = read(sockfd, recvBuff, sizeof(recvBuff)-1)) > 0) {
							recvBuff[n] = 0;

							// Printing bytes if verbose
							if (verbose) { printf("Packet received, %s\n", recvBuff); }

							// Parse bytes to packet
							if (!bytes_to_packet(&file_details, recvBuff)) {
								printf("!! Error converting received bytes to packet. bytes=%s\n", recvBuff);
								exit(EXIT_FAILURE);
							}

							// Break when packet received
							if (strlen(recvBuff) > 0) {
								break;
							}
						}

						// Check the type is correct
						if (file_details.pkt_type != PKT_FILE_DETAILS) {
							if (verbose) { printf("Incorrect packet received, expected PKT_FILE_DETAILS, got %i\n", file_details.pkt_type); }
							exit(EXIT_FAILURE);
						}

						// Print received file details if verbose
						if (verbose) { printf("Received file details for %s\n", file_details.contents[2]); }

						// Create ack packet
						ack_packet = malloc(snprintf(NULL, 0, "{ type:%i ack_num:%s }", PKT_ACK, file_details.contents[0]));
						sprintf(ack_packet, "{ type:%i ack_num:%s }", PKT_ACK, file_details.contents[0]);

						// Creating file
						if (verbose) { printf("Creating file %s\n", file_details.contents[2]); }
						FILE *new_file = fopen(file_details.contents[2], "wb");

						// Checking file was created
						if (new_file == NULL) {
							printf("Failed to create new file");
						}

						// Waiting for server to catch up
						sleep(1);

						// Sending ack
						if (verbose) { printf("Sending ack. ack=%s\n", ack_packet); }
						if (send(sockfd, ack_packet, sizeof(char) * strlen(ack_packet), 0) < 0) {
							printf("Send failed");
							exit(EXIT_FAILURE);
						}

						// Receiving file
						receive_file(new_file, sockfd, atoi(file_details.contents[1]));
						fclose(new_file);

						// Sending ack
						if (verbose) { printf("Sending ack. ack=%s\n", ack_packet); }
						if (send(sockfd, ack_packet, sizeof(char) * strlen(ack_packet), 0) < 0) {
							printf("Send failed");
							exit(EXIT_FAILURE);
						}

						files_received++;
					}
				}
			}

			// Kill process if executing was successful
			exit(EXIT_SUCCESS);
		}

		// Waiting for all child processes to terminate before next actionset
		pid_t wpid;
		int status = 0;
		while ((wpid = wait(&status)) > 0) {
			// Exit main process if error
			if (WEXITSTATUS(status) == EXIT_FAILURE) { exit(EXIT_FAILURE); }
		};

		// Printing new line
		printf("\n");
	}

	return true;
}
