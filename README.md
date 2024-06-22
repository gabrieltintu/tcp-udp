# TINTU Gabriel-Claudiu 323CAb - 2023-2024

## PCOM - Second Assignment: Client-Server App TCP & UDP

### Server Program

The server program begins by initializing three sockets:
- **TCP**: Used for handling TCP client connections.
- **UDP**: Utilized for communication with UDP clients.
- **STDIN**: Allows the server to receive input from the console.

The server runs continuously, listening for incoming events on these sockets.

#### Main Functionality

- **TCP Socket**:
  - Accepts incoming TCP connections from clients.
  - Each time a connection is accepted, it initializes a new socket and a new subscriber.
  - Adds the new socket and subscriber to the poll and the list of subscribers if no client with the same ID already exists.

- **UDP Socket**:
  - Receives messages from UDP clients and processes them.
  - Builds TCP messages from received UDP data and sends them to TCP clients subscribed to the corresponding topic.

- **STDIN Socket**:
  - Receives commands from STDIN (e.g., `exit`).
  - Closes all sockets and terminates the program upon receiving the `exit` command.

#### TCP Subscribers Handling

When a TCP client sends a message, the server processes it as follows:
1. **0 bytes received**: Indicates client exit, leading to client disconnection.
2. **Subscribe**: Subscribes the client to the specified topic.
3. **Unsubscribe**: Unsubscribes the client from the specified topic.

### Subscriber Program

The subscriber program acts as a client that connects to the server to subscribe to topics and receive messages.

It initially creates a TCP socket, connects to the specified server IP address and port, and uses a socket for receiving commands from STDIN.

#### Main Functionality

- **TCP Socket**:
  - Receives messages from the server (sent via UDP) and prints them to STDOUT.
  - Terminates the program if 0 bytes are received, indicating the socket was closed.

- **STDIN Socket**:
  - Sends commands received from STDIN to the server:
    1. **Subscribe**: Subscribes to the specified topic.
    2. **Unsubscribe**: Unsubscribes from the specified topic.

### Other

- Used the TCP laboratory as a starting point to complete the assignment.
- Created a structure to send the received messages from UDP clients to the subscribers, containing: IP, port, topic, type of data, and content.
- Created a structure to retain the subscribers' data: connection status, subscribed topics, socket file descriptor, and client ID.

### Encountered Problems

- **Building the "FLOAT" type message from UDP**: Setting the precision.
  - Solution: Used a `stringstream` and then updated the content.

- **Quick_flow test**:
  - Initially sent messages to clients with the size of the structure.
  - Improved efficiency by sending the actual size of the message first and then the message with that size.
