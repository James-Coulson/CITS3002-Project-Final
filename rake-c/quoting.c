// ---------------------- INCLUDES ---------------------- //

#include "rake-c.h"

// ---------------------- QUOTING FUNCTIONS ---------------------- //

int get_quote(int host) {
	int sockfd = 0;
	int n = 0;
	struct sockaddr_in serv_addr;
	char recvBuff[8192];

	memset(recvBuff, '0', sizeof(recvBuff));
	if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		printf("\n Error : Could not create socket \n");
		return -1;
	}

	serv_addr.sin_family = AF_INET;

	if (count_occurences(hosts[host], ':') == 1) {
		char *host_str = strdup(hosts[host]);
		strtok(host_str, ":");
		int pott = atoi(strtok(NULL, ":"));
		host_str = strdup(hosts[host]);
		serv_addr.sin_port = htons(pott);
		serv_addr.sin_addr.s_addr = inet_addr(strtok(host_str, ":"));
	} else {
		serv_addr.sin_port = htons(port);
		serv_addr.sin_addr.s_addr = inet_addr(hosts[host]);
	}

	// Connecting to server
	if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr))<0) {
		printf("\n Error : Connect Failed - %s : %i\n", hosts[host], port);
		return -1;
	}

	// -- Making and sending quote packet --
	// Getting ack number
	int ack_num = rand_int(0, MAX_RAND_NUM);

	// Making packet
	char *pkt = malloc(snprintf(NULL, 0, "{ type:%i ack_num:%i }", PKT_QUOTE_REQUEST, ack_num));
	sprintf(pkt, "{ type:%i ack_num:%i }", PKT_QUOTE_REQUEST, ack_num);

	// Sending packet
	if (send(sockfd, pkt, sizeof(char) * strlen(pkt), 0) < 0) {
		printf("Send failed");
		return 1;
	}

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

		// ! Need to add timeout and retransmit data.
		// ! Need to add nacks and retransmit
	}

	// Define pkt
	PACKET packet;

	// Getting response from socket
	while((n = read(sockfd, recvBuff, sizeof(recvBuff)-1)) > 0) {
		recvBuff[n] = 0;

		// Printing bytes if verbose
		if (verbose) { printf("Packet received, %s\n", recvBuff); }

		// Parse bytes to packet
		if (!bytes_to_packet(&packet, recvBuff)) {
			printf("!! Error converting received bytes to packet. bytes=%s\n", recvBuff);
			return false;
		}

		// Break when packet received
		if (strlen(recvBuff) > 0) {
			break;
		}
	}

	// Sending ack
	pkt = malloc(snprintf(NULL, 0, "{ type:%i ack_num:%s }", PKT_ACK, packet.contents[0]));
	sprintf(pkt, "{ type:%i ack_num:%s }", PKT_ACK, packet.contents[0]);
	if (send(sockfd, pkt, sizeof(char) * strlen(pkt), 0) < 0) {
		printf("Send failed");
		return 1;
	}

	// Sending close connection packet (no need for ack as the connection will timeout anyway)
	char *close_conn_packet = malloc(snprintf(NULL, 0, "{ type:%i }", PKT_CLOSE_CONN));
	sprintf(close_conn_packet, "{ type:%i }", PKT_CLOSE_CONN);
	if (send(sockfd, close_conn_packet, sizeof(char) * strlen(close_conn_packet), 0) < 0) {
		printf("Send failed");
		return 1;
	}

	close(sockfd);

	// Check packet is PKT_QUOTE_REPONSE
	if (packet.pkt_type == PKT_QUOTE_RESPONSE) { return atoi(packet.contents[1]); }
	else { return -1; }
}

int quote_hosts() {
	// Used to get an execution quote from the different hosts
	//
	// Returns:
	//  - Index in hosts for best server, -1 otherwise

	// Get initial quote
	int pref_host = 0;
	int pref_quote = get_quote(0);

	// Check rest of hosts
	for (int i = 1; i < MAX_HOSTS; i++) {
		if (hosts[i] == NULL) { break; }

		int h_quote = get_quote(i);

		if (pref_quote < h_quote) {
			pref_host = i;
			pref_quote = h_quote;
		}
	}

	return pref_host;
}
