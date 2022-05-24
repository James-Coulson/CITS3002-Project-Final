import os
import socket
import binascii
import time
import random

# Creating an empty list to hold each actionset and it's commands actionsets[i][j]
# where i = the actionset and its number
# and j = the command, which holds dictionaries of each command
actionsets = []

# Define local bool
local = False

# Define verbose bool
verbose = True

# DEFAULT PORT
port = 4999

# Declaring list of hosts
hosts = []

# Packet types
PKT_EXEC = 0                # Execute command straight away and return response     { 'type': int, 'ack_num': int, 'cmd_length': int, 'command': str }
PKT_CLOSE_CONN = 1          # Issued to close the connection                        { 'type': int }
PKT_ACK = 2                 # Issued to acknowledge previous sent packet            { 'type': int, 'ack_num': int }
PKT_TERMINAL_OUTPUT = 3     # Packet thats contents should be printed to terminal   { 'type': int, 'ack_num': int, 'output_length': int, 'output': str }
PKT_FILE_DETAILS = 4		# Contains the information about a file that is going to be transmitted	    { 'type': int, 'ack_num': int, 'filesize': int, 'filename': str }
                            # After the ack for this packet is received it will transmit the file


# File transmission variables
MAX_FILE_BUFFER = 1024      # Maximum amount of bytes that can be transmitted in one buffer

# Timeout variables
CONN_TIMEOUT = 1            # Number of seconds before recv returns
MAX_SILENT_PERIODS = 5      # Number of timeout periods before closing connection
SLEEP_PERIOD = 3            # Number of seconds thread is blocked before reading buffer again
MAX_ACK_SILENT_PERIODS = 4  # Number of timeout periods waiting for an ack before the packet is resent
ACK_SLEEP_PERIOD = 3        # Number of seconds thread is blocked before reading for ack

def text_to_bits(text, encoding='utf-8', errors='surrogatepass'):
	bits = bin(int(binascii.hexlify(text.encode(encoding, errors)), 16))[2:]
	return bits.zfill(8 * ((len(bits) + 7) // 8))

def text_from_bits(bits, encoding='utf-8', errors='surrogatepass'):
	n = int(bits, 2)
	return int2bytes(n).decode(encoding, errors)

def int2bytes(i):
	hex_string = '%x' % i
	n = len(hex_string)
	return binascii.unhexlify(hex_string.zfill(n + (n & 1)))

def packet_to_dict(pkt: bytes) -> dict:
	"""
	Converts a received packet into a dictionary

	:param pkt: Packet to be converted to a dictionary
	:return: dict
	"""
	# Splits data to get individual elements
	pkt_split = pkt.decode('utf-8').split(' ')

	# Checks first and last elements are curly brackets
	if pkt_split[0] != '{' and pkt_split[-1] != '}':
		print("Incomplete packet passed to be converted, {}".format(pkt))
		raise ValueError("Packet being parsed is not complete ( does not start/end with { and } )")

	if int(pkt_split[1][5:]) == PKT_EXEC:               # If the received packet is for executing a command by itself
		# Convert packet to dictionary
		ret = { 'type': int(pkt_split[1][5:]), 'ack_num': int(pkt_split[2][8:]), 'files': int(pkt_split[3][6:]), 'cmd_length': int(pkt_split[4][8:]), 'command': pkt_split[5][4:], }

		# Convert binary to string command
		ret['command'] = text_from_bits(ret['command'])
	elif int(pkt_split[1][5:]) == PKT_CLOSE_CONN:       # If the packet is to close the connection
		# Convert packet to dictionary
		ret = {'type': int(pkt_split[1][5:]), }
	elif int(pkt_split[1][5:]) == PKT_ACK:
		# Convert packet to dictionary
		ret = { 'type': int(pkt_split[1][5:]), 'ack_num': int(pkt_split[2][8:]), }
	elif int(pkt_split[1][5:]) == PKT_TERMINAL_OUTPUT:
		# Convert packet to dictionary
		ret = { 'type': int(pkt_split[1][5:]), 'ack_num': int(pkt_split[2][8:]), 'files': int(pkt_split[3][6:]), 'output_length': int(pkt_split[4][14:]), 'output': pkt_split[5][7:], }

		if ret['output_length'] > 0:
			# Ensuring bits are int if it isn't empty
			ret['output'] = int(ret['output'])
			# Convert binary to string output
			ret['output'] = text_from_bits(str(ret['output']))

	elif int(pkt_split[1][5:]) == PKT_FILE_DETAILS:     # If packet is file details
		# Convert packet to dictionary
		ret = { 'type': int(pkt_split[1][5:]), 'ack_num': int(pkt_split[2][8:]), 'filesize': int(pkt_split[3][9:]), 'filename': pkt_split[4][9:], }

		# Convert binary to string
		ret['filename'] = text_from_bits(ret['filename'])
	else: # Command type was not recognised
		raise ValueError("Command type of packet not recognised: type={}, from={}".format(int(pkt_split[1][9:]), hosts[0]))

	# Return dictionary
	return ret

def is_remote(cmd):
	'''
	Checks whether the command begins with "remote"

	Params:
	- cmd: Command to be checked

	Return:
	- Returns true if command is remote and false otherwise
	'''
	if (cmd.strip().split("-")[0] == "remote"):
		return True
	else:
		return False

def parse_port(buffer):
	''' Gets the port from buffer
	
	 Params;
	 - buffer: the buffer
	
	 Return:
	 - the port
	'''
	return buffer.strip().split()[-1]


def parse_hosts(buffer):
	'''
	 Gets hosts from buffer
	
	 Params;
	  - buffer: the buffer
	'''
	return buffer.strip().split()[2:]2

def parse_file(path):
	'''
	 Used to parse a given file into the actionsets data-structure
	
	 Params:
	  - path: The relative pathname for the file
	
	 Return:
	  - Returns true if file is successfully parsed and false otherwise
	
	 Assumptions:
	  (*1) Assumes that entire line of file will fit in the buffer (treats each buffer as new line)
	  (*2) Assumes comment "#" will only be at start of line
	'''
	if (verbose):
		print("----------------- Parsing Rakefile ----------------\n\n")
		print("path " + path + "\n")

	f = open(path, 'r')
	if f.closed: # File fails to open
		return False
	lines = f.readlines()

	if (verbose):
		print("\n\t\t*Printing Rakefile*\n\n")
	
	nactionset = -1
	ncommand = -1
	
	# [0] represents whether port has been parsed
	# [1] represents whether hosts have been parsed
	header_parsed = [False, False]

	for buffer in lines:	# buffer represents each line
		if (verbose):
			print(buffer)
		
		if ((buffer[0] == '#') or (buffer[0] == '\n')):		# skipping empty / commented lines
			continue
	
		if ((header_parsed[0] == False) or (header_parsed[1] == False)): # parses ports and hosts
			if (buffer[0] == 'P'):
				header_parsed[0] = True
				global port
				port = parse_port(buffer)
			elif (buffer[0] == 'H'):
				header_parsed[1] = True
				global hosts 
				hosts = list(parse_hosts(buffer))
		else: # Parse actionsets
			tab_count = buffer.count("\t", 0, 2)
			if (tab_count == 0): # New actionset
				nactionset += 1
				ncommand = -1
				actionsets.append([]) # Creates new list index for action set
			elif (tab_count == 1): # New command
				ncommand += 1

				# Creates a new dict representing each command
				if (is_remote(buffer[1:])):
					actionsets[nactionset].append({
						"cmd" : buffer[8:].strip(),
						"remote" : True,
						"req_files" : []
					})
				else:
					actionsets[nactionset].append({
						"cmd" : buffer[1:].strip(),
						"remote" : False,
						"req_files" : []
					})
			
			elif (tab_count == 2): # Parses the required file into the command dict
				actionsets[nactionset][ncommand]["req_files"] += buffer.strip().split()[1:]
				
	if (verbose):
		print("\n\t\t*End Rakefile*\n")
		print("\n------------ Finished Parsing Rakefile ------------\n\n")


	print("gggg {}".format(hosts))

	return True

def execute_locally():
	if (verbose):
		print("\n------------- Executing Actionsets Locally ------------\n")
	
	i = 0
	while (i < len(actionsets)):
		j = 0
		while (j < len(actionsets[i])):
			current_cmd = actionsets[i][j]["cmd"]
			os.system(current_cmd)
			j += 1
		i += 1

	return True

def wait_for_ack(conn, ack_num: int, pkt: str) -> bool:
	"""
	Called when a connection is waiting for an ack

	:param conn: Connection waiting for ack
	:param ack_num: Ack number waiting for
	:param pkt: The packet to be resent if ack not received
	:return: True if ack received, False otherwise
	"""
	# Print waiting for ack
	if verbose:
		print("Waiting for ack. ack_num={}".format(ack_num))

	# Variables for ack
	ack_timeout = 0

	# Waiting for ack
	while True:
		# Get bytes from buffer
		try:
			ack_buff = conn.recv(4096)
		except socket.timeout as e:
			# Increments timeout counter
			ack_timeout += 1

			# Print timeout counter if verbose
			if verbose:
				print("Ack timeout counter = {}".format(ack_timeout))

			# Checks if max timeout periods have been reached
			if ack_timeout <= MAX_ACK_SILENT_PERIODS:
				continue

			# Reset ack_timeout
			ack_timeout = 0

			# Sending pkt again
			conn.send(pkt.encode('utf-8'))

			# Continue
			continue

		if ack_buff.decode('utf-8') != '':
			# Convert bytes to dictionary
			try:
				ack_packet = packet_to_dict(ack_buff)
			except ValueError as e:
				print(e)
				return False

			# Checks that packet is correct
			if ack_packet['type'] == PKT_ACK and ack_packet['ack_num'] == ack_num:
				if verbose:
					print("Received ack. ack_num={}".format(ack_packet['ack_num']))
				break
			else:
				raise ValueError("Wrong packet was received instead of ack. packet={}".format(ack_packet))

	return True

def execute():
	"""Used to send commands to different servers and handle output/file from the servers
	
	 Return:
	  - true if successfull, false otherwise
	
	 Assumptions:
	  (*1) Assumes that there is only one server connection
	"""
	
	if verbose:
		print("----------------- Executing Actionsets ----------------\n\n")
	
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	if verbose:
		print("\nConnection to {}: {}".format(hosts[0], port))
	
	sock.connect((hosts[0], int(port)))

	for i in range(len(actionsets)):
		if verbose:
			print("Current actionset number" + str(i+1))
		
		curr_actset = actionsets[i]
		for j in range(len(curr_actset)):
			curr_cmd = curr_actset[j]

			if curr_cmd["remote"] == False:
				if verbose:
					print("Executing command locally: {}\n".format(curr_cmd["cmd"]))
				
				os.system(curr_cmd["cmd"])
				continue

			# Creating Packet
			cmd_len = len(curr_cmd["cmd"])
			cmd_type = PKT_EXEC
			cmd_files = len(curr_cmd["req_files"])
			ack_num = random.randint(0, 9999)
			
			# Converting packet cmd dict to bits
			packet = "{{ type:{} ack_num:{} files:{} cmd_len:{} cmd:{} }}".format(cmd_type, ack_num, cmd_files, cmd_len, text_to_bits(curr_cmd["cmd"]))
			
			if verbose:
				print("Made packet: {}\n".format(packet))
				print("\nExecuting command: {}\n".format(curr_cmd["cmd"]))
			
			# Sleep to wait for server to catch up
			time.sleep(1)

			# Sending packet to server
			sock.send(packet.encode('utf-8'))

			if verbose:
				print("Sent\n")
				print("Waiting for ack\n")

			if not wait_for_ack(sock, ack_num, packet):
				print("ack failed \n")
				break

			# SENDING FILES
			if cmd_files > 0:
				i = 0
				while i < cmd_files:
					file_path = curr_cmd["req_files"][i]

					f = open(file_path, 'rb')
					if f.closed: # File fails to open
						print("File failed to open: {}\n".format(file_path))
					
					file_size = os.path.getsize(file_path)
					ack_num = random.randint(0, 9999)

					file_path = file_path.split("/")[-1]

					if verbose:
						print("Filename: {} \n Filesize: {}".format(file_path, file_size))


					file_details_pkt = "{{ type:{} ack_num:{} filesize:{} filename:{} }}".format(PKT_FILE_DETAILS, ack_num, file_size, text_to_bits(file_path))

					if verbose:
						print("File details packet: {}".format(file_details_pkt))

					sock.send(file_details_pkt.encode('utf-8'))

					if not wait_for_ack(sock, ack_num, file_details_pkt):
						print("ack failed \n")
						break
					
					while file_size > 0:
						buffer = f.read(min(file_size, MAX_FILE_BUFFER))

						if verbose:
							print("sending {}".format(buffer))

						sock.send(buffer)

						file_size -= len(buffer)
					
					if not wait_for_ack(sock, ack_num, file_details_pkt):
						print("ack failed \n")
						break
					
					time.sleep(3)
					i += 1

			# Int counts number of silent period for purpose of closing inactive connections
			silent_count = 0
			while True:
				# Obtains data from connect and handles EOFError
				try:
					byte_recvd = sock.recv(2*4096)
				except EOFError as e:
					print("Got error when receiving data: {}".format(e))
					break

				
				# If the data received is empty (nothing sent)
				if byte_recvd.decode('utf-8') == '':
					# If number of silent period exceeds maximum
					if silent_count > MAX_SILENT_PERIODS:
						# Print if verbose
						if verbose:
							print("Closed connection with {}".format(hosts[0]))
						# Break to exit loop
						break

					# Increment silent count
					silent_count += 1

					# Print conn status
					if verbose:
						print("{} silent_count = {}".format(hosts[0], silent_count))

					# Sleep thread
					time.sleep(SLEEP_PERIOD)

					# Go back to top
					continue
				else:
					if verbose:
						print('Received bytes: {} from {}'.format(byte_recvd, hosts[0]))
					
					pkt = packet_to_dict(byte_recvd)
					
					if pkt['type'] == PKT_TERMINAL_OUTPUT:
						print(pkt['output'])

						if verbose:
							print("Sending Ack num=".format(pkt['ack_num']))
						ack_packet = "{{ type:{} ack_num:{} }}".format(PKT_ACK, pkt['ack_num'])
						
						sock.send(ack_packet.encode('utf-8'))

						 # Checking if files are required
						if pkt['files'] > 0:
							if verbose:
								print("Files need to be downloaded. files={}".format(pkt['files']))

							# Getting files
							files_received = 0
							while files_received < pkt['files']:
								# Waiting for first PKT_FILE_DETAILS
								try:
									file_details_bytes = sock.recv(4096)
								except socket.timeout as e:
									continue
									# Add timeout counter
									# Send PKT_FAILED_EXEC when number of timeouts occur

								# Print bytes received if verbose
								if verbose:
									print("Received bytes {}".format(file_details_bytes))

								# Converting bytes to dictionary
								file_details_packet = packet_to_dict(file_details_bytes)

								# Printing converted packet
								if verbose:
									print("Converted to dictionary: {}".format(file_details_packet))

								# Making new file in dict
								new_file = open(file_details_packet['filename'], "wb")

								# Send ack
								sock.send("{{ type:{} ack_num:{} }}".format(PKT_ACK, file_details_packet['ack_num']).encode('utf-8'))

								# Receive file
								new_file_data = ''
								while new_file_data == '':       # may need to add timeouts here
									try:
										new_file_data = sock.recv(min(file_details_packet['filesize'], 1024))
									except socket.timeout as e:
										continue

								filesize = file_details_packet['filesize']

								# While new_file_data is not empty
								while new_file_data:
									# Printing data received
									if verbose:
										print("Got new file data : {}".format(new_file_data))

									# Writing data to new file
									new_file.write(new_file_data)
									filesize -= len(new_file_data)

									if filesize > 0:
										try:
											new_file_data = sock.recv(min(1024, filesize))
											continue
										except socket.timeout as e:
											new_file_data = b''
											continue

									# Closing new file
									new_file.close()

									# Checking file is complete
									if os.path.getsize(file_details_packet['filename']) != file_details_packet['filesize']:
										print("!!!!!!!!!! Error file received was not the size given !!!!!!!!!!, path={}, given size={}, actual size={}".format(file_details_packet['filename'], file_details_packet['filesize'], os.path.getsize(file_details_packet['filename'])))
									break

								# Increment files_received
								files_received += 1

								# Send ack
								sock.send("{{ type:{} ack_num:{} }}".format(PKT_ACK, file_details_packet['ack_num']).encode('utf-8'))


						if verbose:
							print("Sending ack. ack={}\n".format(ack_packet))

						sock.send(ack_packet.encode('utf-8'))
						time.sleep(1)
					break
	
	if verbose:
		print("Sending close conn packet\n")
	sock.send("{ type:1 }".encode('utf-8'))
					
		

def driver():
	print("\n")
	path = "test_rakefiles/building_rakefile.txt"
	
	if (not parse_file(path)):
		print("\n!! Error when parsing Rakefile, check that the path is correct !!\n")
		print("path: " + path + "\n")
	
	if (local):
		if (not execute_locally()):
			print("\n!! Error when attempting to execute actionsets locally!!\n")
	
	else:
		execute()

if (__name__ == "__main__"):
	driver()





