# Imports
import socket
import os
import time
import binascii
import uuid
from random import randint
from shutil import rmtree

# -- Global Constants --

# Packet types
PKT_EXEC = 0                # Execute command straight away and return response                         { 'type': int, 'ack_num': int, 'files':bool, 'cmd_length': int, 'command': str }
PKT_CLOSE_CONN = 1          # Issued to close the connection                                            { 'type': int }
PKT_ACK = 2                 # Issued to acknowledge previous sent packet                                { 'type': int, 'ack_num': int }
PKT_TERMINAL_OUTPUT = 3     # Packet thats contents should be printed to terminal                       { 'type': int, 'ack_num': int, 'files':bool, 'output_length': int, 'output': str }
PKT_FILE_DETAILS = 4		# Contains the information about a file that is going to be transmitted	    { 'type': int, 'ack_num': int, 'filesize': int, 'filename': str }
                            # After the ack for this packet is received it will transmit the file
PKT_QUOTE_REQUEST = 5		# Contains information about a quote wanted by the client					{ 'type': int, 'ack_num': int }
PKT_QUOTE_RESPONSE = 6      # Contains quote requested                                                  { 'type': int, 'ack_num': int, 'quote': int }

# Timeout variables
CONN_TIMEOUT = 1            # Number of seconds before recv returns
MAX_SILENT_PERIODS = 2      # Number of timeout periods before closing connection
SLEEP_PERIOD = 3            # Number of seconds thread is blocked before reading buffer again
MAX_ACK_SILENT_PERIODS = 4  # Number of timeout periods waiting for an ack before the packet is resent
ACK_SLEEP_PERIOD = 3        # Number of seconds thread is blocked before reading for ack

# Ack constants
MAX_RAND_NUM = 99999        # Max rand number used for acknowledgment numbers

# File transmission variables
MAX_FILE_BUFFER = 1024      # Maximum amount of bytes that can be transmitted in one buffer

# Verbose
verbose = False              # If the server is run in verbose mode


def remove_char(string, n):
    """
    Used to remove nth character from a string

    :param string: String
    :param n: Index of character to be removed
    :return: String with character removed
    """
    first = string[:n]
    last = string[n + 1:]
    return first + last


def text_to_bits(text, encoding='utf-8', errors='surrogatepass'):
    """
    Used to convert text to binary

    :param text: Text to be converted
    :param encoding: Encoding used
    :param errors:  Error handling
    :return: Binary version of text
    """
    bits = bin(int(binascii.hexlify(text.encode(encoding, errors)), 16))[2:]
    return bits.zfill(8 * ((len(bits) + 7) // 8))


def text_from_bits(bits, encoding='utf-8', errors='surrogatepass'):
    """
    Used to convert binary to text

    :param bits: Binary to be converted to text
    :param encoding: Encoding used
    :param errors: Error handling
    :return: ASCII version of binary
    """
    n = int(bits, 2)
    return int_to_bytes(n).decode(encoding, errors)


def int_to_bytes(i):
    """
    Converts and integer to bytes

    :param i: integer
    :return: bytes version of integer
    """
    hex_string = '%x' % i
    n = len(hex_string)
    return binascii.unhexlify(hex_string.zfill(n + (n & 1)))


def destuff_string(string: str, stuffed_char: str) -> str:
    """
    Destuffs a given string using a given character

    :param string: String to be destuffed
    :param stuffed_char: Character used to stuff
    :return: Unstuffed string
    """

    # Variables to count number of chars removed and position in string
    count = 1
    i = 0

    # Iterate through string removing stuffed characters
    while i < len(string) - count:
        # If character is stuffed character
        if string[i] == stuffed_char:
            # If next character is stuffed character
            if string[i + 1] == stuffed_char:
                # Remove repeated stuffed character and increment count
                count += 1
                string = remove_char(string, i)
            else:
                # Replace stuffed character with ' '
                string = string[0:i] + ' ' + string[i + 1:]
        # Increment i
        i += 1

    # Return destuffed string
    return string


def stuff_string(string: str, stuffed_char: str) -> str:
    """
    Stuffs a string using the given delimiter

    :param string: String to be stuffed
    :param stuffed_char: The character to be stuffed
    :return: The stuffed string
    """
    temp = string
    temp = temp.replace(stuffed_char, stuffed_char + stuffed_char)
    temp = temp.replace(' ', stuffed_char)
    return temp


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

    elif int(pkt_split[1][5:]) == PKT_ACK:              # If packet is an acknowledgement
        # Convert packet to dictionary
        ret = { 'type': int(pkt_split[1][5:]), 'ack_num': int(pkt_split[2][8:]), }

    elif int(pkt_split[1][5:]) == PKT_FILE_DETAILS:     # If packet is file details
        # Convert packet to dictionary
        ret = { 'type': int(pkt_split[1][5:]), 'ack_num': int(pkt_split[2][8:]), 'filesize': int(pkt_split[3][9:]), 'filename': pkt_split[4][9:], }

        # Convert binary to string
        ret['filename'] = text_from_bits(ret['filename'])

    elif int(pkt_split[1][5:]) == PKT_QUOTE_REQUEST:
        # Convert packet to dictionary
        ret = {'type': int(pkt_split[1][5:]), 'ack_num': int(pkt_split[2][8:]), }

    else: # Command type was not recognised
        raise ValueError("Command type of packet not recognised: type={}, from={}".format(int(pkt_split[1][9:]), addr))

    # Return dictionary
    return ret


def send_ack(conn, ack_num):
    """
    Sends an ack through the connection

    :param conn: Connection
    :param ack_num: Ack number
    """
    ack = "{{ type:{} ack_num:{} }}".format(PKT_ACK, ack_num)
    conn.send(ack.encode("utf-8"))


def exec_command(command: str) -> str:
    """
    Used to execute a system command in the cwd

    :param command: Command to be executed
    :return: Output from command
    """
    stream = os.popen(command)
    output = stream.read()
    return output


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
            ack_buff = conn.recv(1024)
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


def create_new_folder():
    """
    Called to make a new folder in the cwd

    :return: (path, current_dir)
    """
    current_dir = os.getcwd()
    folder = "{}".format(str(uuid.uuid4()))
    path = os.path.join(current_dir, folder)
    if not os.path.exists(path):
        os.makedirs(path)

    return path, current_dir


def create_socket(port: int) -> socket.socket:
    """
    Creates a network socket with the specified port

    :param port: Port number to be used for socket
    :return: Open socket
    """
    # Printing if verbose
    if verbose:
        print("Creating socket with port {}".format(port))

    # Creating socket object
    sock = socket.socket()

    # sock.setblocking(False)

    # Binding socket to port
    sock.bind(('', port))

    # Return socket
    return sock


def handle_conn(conn, addr):
    """
    Called when a connection is established to handle interactions with client

    :param conn: Connection object
    :param addr: Address
    :return: returns when connection is closed
    """
    # Int counts number of silent period for purpose of closing inactive connections
    silent_count = 0

    # Entire while loop
    while True:
        # Obtains data from connect and handles EOFError
        try:
            byte_recvd = conn.recv(4096)
        except socket.timeout as e:
            continue

        # If the data received is empty (nothing sent)
        if byte_recvd.decode('utf-8') == '':
            # If number of silent period exceeds maximum
            if silent_count > MAX_SILENT_PERIODS:
                # Print if verbose
                if verbose:
                    print("Closed connection with {}".format(addr))
                # Break to exit loop
                break

            # Increment silent count
            silent_count += 1

            # Print conn status
            if verbose:
                print("{} silent_count = {}".format(addr, silent_count))

            # Sleep thread
            time.sleep(SLEEP_PERIOD)

            # Go back to top
            continue

        # Reset silent count if data received
        silent_count = 0

        # print received bytes if verbose
        if verbose:
            print('Received bytes: {} from {}'.format(byte_recvd, addr))

        # Convert received bytes to packet (THIS IS WHERE PACKET CHECKS SHOULD BE DONE)
        packet = dict()
        try:
            packet = packet_to_dict(byte_recvd)
        except Exception as e:
            # !! Return a nack for retransmission is exception thrown !!!!!!!!!!!!!!
            if verbose:
                print("Error with packet conversion: packet={}".format(byte_recvd))

        # Print parsed packet if verbose
        if verbose:
            print("Packet parsed to {}".format(packet))

        # Output parsed packet dictionary
        if verbose:
            print("Parse bytes to packet: {} from {}".format(packet, addr))

        if packet['type'] == PKT_EXEC:  # If the command should be executed
            # Sending ack back to client needs to be modified to contain ack_num
            send_ack(conn, packet['ack_num'])

            # Create folder to run exec in
            path, current_dir = create_new_folder()

            # Move to new directory
            os.chdir(path)

            # Checking if files are required
            if packet['files'] > 0:
                if verbose:
                    print("Files need to be downloaded. files={}".format(packet['files']))

                # Getting files
                files_received = 0
                while files_received < packet['files']:
                    # Waiting for first PKT_FILE_DETAILS
                    try:
                        file_details_bytes = conn.recv(4096)
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
                    send_ack(conn, file_details_packet['ack_num'])

                    # Receive file
                    new_file_data = ''
                    while new_file_data == '':       # may need to add timeouts here
                        try:
                            print(min(file_details_packet['filesize'], 1024))
                            new_file_data = conn.recv(min(file_details_packet['filesize'], 1024))
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
                                new_file_data = conn.recv(min(1024, filesize))
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
                    send_ack(conn, file_details_packet['ack_num'])

            # Print new cwd to terminal
            if verbose:
                print("CWD: {}".format(os.getcwd()))

            # Printing path of new folder if verbose
            if verbose:
                print("Making folder path={}".format(path))

            # Print command if verbose
            if verbose:
                print("Executing command: {}".format(packet['command']))

            # Checking if any files were made
            old_files = os.listdir()

            # Printing files if verbose
            if verbose:
                print("Files before execution in cwd: files={}".format(old_files))

            # Executing command
            output = exec_command(packet['command'])

            # Checking if any files were made
            new_files = os.listdir()

            # Printing files if verbose
            if verbose:
                print("Files after execution in cwd: files={}".format(new_files))

            # Checking files created
            new_files = list(set(new_files) - set(old_files))

            # Printing files created
            if verbose:
                print("Files created were: {}".format(new_files))

            # binary output
            if output != "":
                binary_output = text_to_bits(output)
            else:
                binary_output = ""

            if verbose:
                print("Printing binary output and original output\n", binary_output, '\n', output)

            # Creating packet for response
            ack_number = randint(0, MAX_RAND_NUM)
            pkt = "{{ type:{} ack_num:{} files:{} output_length:{} output:{} }}".format(PKT_TERMINAL_OUTPUT, ack_number, len(new_files), len(binary_output), binary_output)

            # Print packet
            if verbose:
                print("Made packet: {}".format(pkt))

            # Sending packet
            conn.send(pkt.encode('utf-8'))

            # Waiting for ack
            wait_for_ack(conn=conn, ack_num=ack_number, pkt=pkt)

            # Sending new files
            for file in new_files:
                # Get file size
                filesize = os.path.getsize(file)

                # Making PKT_FILE_DETAILS
                ack_number = randint(0, MAX_RAND_NUM)
                pkt = "{{ type:{} ack_num:{} filesize:{} filename:{} }}".format(PKT_FILE_DETAILS, ack_number, filesize, text_to_bits(file))

                # Printing packet if verbose
                if verbose:
                    print("Made packet {}".format(pkt))

                # Sending packet
                conn.send(pkt.encode('utf-8'))

                # Waiting for ack
                wait_for_ack(conn, ack_number, pkt)

                # Open file
                file = open(file, "rb")

                time.sleep(1)

                # Send file
                while filesize > 0:
                    buffer = file.read(min(filesize, MAX_FILE_BUFFER))

                    print("sending {}".format(buffer))

                    conn.send(buffer)

                    filesize -= len(buffer)

                # Wait for ack
                wait_for_ack(conn, ack_number, pkt)

            # Move back to main directory
            os.chdir(current_dir)

            # Print new directory to terminal and print deleting old file
            if verbose:
                print("CWD: {}".format(os.getcwd()))
                print("Deleting file. path={}".format(path))

            # Deleting directory
            rmtree(path)

            continue

        elif packet['type'] == PKT_CLOSE_CONN:
            # Print closing connection if verbose
            if verbose:
                print("Closing connection from {}".format(addr))

            # Closing connection and returning
            conn.close()
            return

        elif packet['type'] == PKT_QUOTE_REQUEST:
            # Sending ack
            pkt = "{{ type:{} ack_num:{} }}".format(PKT_ACK, packet['ack_num'])
            conn.send(pkt.encode('utf-8'))

            # Get quote
            quote = randint(0, 100)

            # Print quote
            if verbose:
                print("Sending quote {}".format(quote))

            # Making response
            ack_num = randint(0, MAX_RAND_NUM)
            pkt = "{{ type:{} ack_num:{} quote:{} }}".format(PKT_QUOTE_RESPONSE, ack_num, quote)

            # Sending response
            conn.send(pkt.encode('utf-8'))

            # Waiting for ack
            wait_for_ack(conn, ack_num, pkt)

        # Sleep thread
        time.sleep(SLEEP_PERIOD)

    # Close connection and returning
    conn.close()
    return


if __name__ == '__main__':
    # Creating socket
    sock = create_socket(4998)

    # Calls wait to wait for connections
    sock.listen(5)

    if verbose:
        print("Waiting for connections")

    # Accepting sockets
    while True:
        # Establish connection with client
        conn, addr = sock.accept()

        # Print new connection if verbose
        if verbose:
            print("Got connection from {}".format(addr))

        # Fork to handle connection on different process
        pid = os.fork()

        if pid > 0: # Process is the parent process
            # Close connection
            conn.close()
        else:
            # Call handle_conn
            conn.settimeout(CONN_TIMEOUT)
            handle_conn(conn, addr)
            exit()
