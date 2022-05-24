// ---------------------- INCLUDES ---------------------- //

#include "rake-c.h"

// ---------------------- FILE ---------------------- //

int main(int argc, char *argv[]) {
	// Creating new line
	printf("\n");

	// Defining path of Rakefile
	char *path = argv[1];

	// Parsing command line arguments
	for (int i = 2; i < argc; i++) {
		if (strcmp(argv[i], "-v") == 0) { verbose = true; }
		else if (strcmp(argv[i], "-l") == 0) { local = true; }
	}

	// Parsing Rakefile
	if (!parse_file(path)) {
		// If error occurs print error and exit with failure
		printf("\n!! Error when parsing Rakefile, check that the path is correct !!\n");
		printf("path: %s\n", path);
		exit(EXIT_FAILURE);
	}

	// Networking

	if (local) {
		// Executes all commands locally (irrespective of if they are defined as remote)
		if (!execute_locally()) {
			// If error occurs print error and exit with failure
			printf("\n!! Error when attempting to execute actionsets locally!!\n");
			exit(EXIT_FAILURE);
		}
	} else {
		if (!execute()) {
			exit(EXIT_FAILURE);
		}
	}
}
