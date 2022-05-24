// ---------------------- INCLUDES ----------------------

#include "rake-c.h"

// ---------------------- UTILITY FUNCTIONS  ---------------------- //

bool is_remote(const char *cmd) {
	// Used to check whether a given command has 'remote-' at the beginning of it
	//
	// Params:
	//  - cmd: Command to be checked
	//
	// Return:
	//  - Returns true if command is remote and false otherwise

	// Checking if string begins with 'remote-'
	if(strncmp(cmd, "remote-", strlen("remote-")) == 0) { return true; }
	return false;
}

int count_occurences(char *string, char c) {
	// Counts the number of occurences of a character in a string
	//
	// Params:
	//  string - String to have chars counted
	//  char - Character to count in string
	//
	// Return:
	//  - Number of occurences in string

	int count = 0;
	for (int i = 0; i < strlen(string); i++) { if (string[i] == c) { count ++; } }
	return count;
}

bool string_to_binary(char *dest, char *source) {
	// Used to convert a string to binary
	//
	// Params:
	//  source - String to be converted to binary
	//  dest - String to store binary
	//
	// Returns:
	//  - true if successful, false otherwise

	// Checks source is not empty
    if (source == NULL) { return false; }

	// Preparing dest
	dest[0] = '\0';

	// Convert string to binary
    for (size_t i = 0; i < strlen(source); ++i) {
        char ch = source[i];
        for(int j = 7; j >= 0; --j){
            if(ch & (1 << j)) {
                strcat(dest,"1");
            } else {
                strcat(dest,"0");
            }
        }
    }

	return true;
}

int rand_int(int lower, int upper) {
	// Generates a random number between the lower and upper bound
	//
	// Params:
	//  lower - Minimum random number
	//  upper - Maximum random number
	//
	// Returns:
	//  - Random int in range [lower, upper]

	int num = rand() % (upper - lower + 1) + lower;
	return num;
}

bool binary_to_string(char *dest, char *source) {
	// Used to convert binary to string
	//
	// Params:
	//  source - Binary to be converted to a string
	//  dest - String to store the converted string
	//
	// Returns:
	//  - true if succesfull, false otherwise

	// Checks source is not empty
	if (source == NULL) { return false; }

	// Defining variables
	int length = strlen(source) / 8;
	char binary[9];
	char temp[2];

	// Preparing char arrays
	dest[0] = '\0';
	temp[1] = '\0';
	binary[8] = '\0';

	// Iterate through binary converting to characters
	for (int i = 0; i < length; i++) {
		// Get next byte
		for (int j = 0; j < 8; j++) {
			binary[j] = source[i*8 + j];
		}

		// Convert binary to char
		temp[0] = strtol(binary, 0, 2);

		// Add char to end of string
		strcat(dest, temp);
	}

	// Return true
	return true;
}
