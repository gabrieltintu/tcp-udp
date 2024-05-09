# TINTU Gabriel-Claudiu 323CAb - 2023-2024

PCOM - second assignment
Client-server app TCP & UDP


** Server program:

The server program begins by initializing three sockets:
    - TCP: Used for handling TCP client connections.
    - UDP: Utilized for communication with UDP clients.
    - STDIN: Allows the server to receive input from the console.

The server runs continuously, listening for incoming events on these sockets.

* Main Functionality:

TCP Socket:
    - Accepts incoming TCP connections from clients.
    - Everytime a connection is accepted initialize a new socket
      and a new subscriber. Add them to the poll and the list of subscribers
      if no client with the same ID already exists.
    
UDP Socket:
    - Receives messages from UDP clients and processes them.
    - Builds TCP messages from received UDP data and sends them to TCP clients
      subscribed to the corresponding topic.

STDIN Socket:
    - Receives command from STDIN (exit).
      -> Close all sockets and terminate the program.

TCP Subscribers handling:
    When a TCP client sends a message the server processes it:
        1. 0 bytes received (meaning we had an exit in subscriber)
           -> disconnects the client
        2. subscribe -> subscribe the client to the topic
        3. unsubscribe -> unsubscribe the client from the topic


** Subscriber program:

The subscriber program follows a similar structure to the server program,
but it acts as a client connecting to the server to subscribe to topics
and receive messages.

It initially creates a TCP socket and connects to the specified server
IP address and port and a socket used for receiving commands from stdin.

* Main Functionality:

TCP Socket:
    - Receives messages from server (the ones sent by UDP)
      and prints them to STDOUT.
    - If the receiving bytes is 0 means that the socket was close
      and we need to terminate the program.

STDIN Socket:
    - Upon receiving commands from STDIN, send the command to the server
        1. subscribe topic
        2. unsubscribe topic


** Other:

- used the TCP laboratory as a starting point to complete the assignment

- created a structure to send the received messages from UDP clients
to the subscribers; the structure contains the: ip, port, topic, type of data
content;

- created a structure to retain the subscribers data: connection status,
subscribed topics, socket file descriptor, and the client ID.


** Encountered problems:

- building the "FLOAT" type message from UDP, how to set the precision
    Used a stringstream and then updated the content.

- in the quick_flow test
    I was initially sending the message to the clients with the size
    of the structure.
    I figured out that I could make it more efficient by sending first
    the actual size of the message and then the message with that size.
