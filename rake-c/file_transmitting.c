// ---------------------- INCLUDES  ---------------------- //

#include "rake-c.h"

// ---------------------- NETWORKING FUNCTIONS  ---------------------- //

void send_file(FILE *fp, int sockfd) {
	fseek(fp, 0, SEEK_END);
    long filesize = ftell(fp);
    rewind(fp);

	if (filesize > 0) {
        char buffer[1024];
        do {
            size_t num = MIN(filesize, sizeof(buffer));
            num = fread(buffer, 1, num, fp);
			send(sockfd, buffer, num, 0);
            filesize -= num;
        } while (filesize > 0);
    }
}

bool read_data(int sockfd, void *buf, int buflen) {
    unsigned char *pbuf = (unsigned char *) buf;

    while (buflen > 0) {
        int num = recv(sockfd, pbuf, buflen, 0);
        // if (num == 0) {return false;}
        pbuf += num;
        buflen -= num;
    }

    return true;
}

bool receive_file(FILE *fp, int sockfd, int fsize) {
	int filesize = fsize;

	if (filesize > 0) {
		char buffer[1024];
        do {
            int num = MIN(filesize, sizeof(buffer));
            if (!read_data(sockfd, buffer, num)) {
				printf("hello boy\n");
				return false; }

            int offset = 0;
            do {
				if (verbose) { printf("writning %s ::: %i\n", buffer, num); }
                size_t written = fwrite(&buffer[offset], 1, num-offset, fp);
                // if (written < 1) { return false; }
                offset += written;
            } while (offset < num);
            filesize -= num;
        } while (filesize > 0);
	}

	return true;
}
