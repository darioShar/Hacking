compile with make, as usual.

The server is started with ./server [port] [max_num_connection], and will listen on any communication comming on tcp port [port].
It is a multithreaded tcp server accepting at most [max_num_connection] concurrent connections. It is also the size of the backlog_queue for the tcp port.

The client is a singlethreaded tcp client continuously sending syn messages (only ip and tcp header) to a destination port and host. Source port and source host are generated at random.
We're making use of raw sockets so this program must be run in root.

In order to use syn_flood.py just replace the target ip address and port at lines 35 and 36, then launch the program and indicate the number of SYN packets to be sent.
