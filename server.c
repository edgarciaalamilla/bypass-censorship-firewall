/*
 * Copyright (c) 2018, Hammurabi Mendes.
 * License: BSD 2-clause
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#include "networking.h"
#include "tls.h"

#define BUFFER_SIZE 1024

#define MAX(A, B) ((A) > (B) ? (A) : (B))

#define MODE_E 0
#define MODE_D 1

int handle_client_encrypt(int decrypt_socket);
int handle_client_decrypt(int client_socket);

int flush_buffer(int socket, char *buffer, int ntowrite);
int flush_buffer_ssl(SSL *ssl, char *buffer, int ntowrite);

int forward_connection(int protected_socket, SSL *protected_ssl, int unprotected_socket);

void print_address_information(char *template, struct sockaddr *address, int address_size);

static int mode;
static char *local_port;
static char *destination_host;
static char *destination_port;

static SSL_CTX *tls_context;

int main(int argc, char **argv) {
	int result;

	// Argument parsing
	if(argc < 4) {
		fprintf(stderr, "Usage: server [E|D] <local_port> <proxy_host> <proxy_port>\n");

		return -1;
	}

	if(strcmp(argv[1], "E") == 0) {
		mode = MODE_E;
	}

	else if(strcmp(argv[1], "D") == 0) {
		mode = MODE_D;
	}

	else {
		fprintf(stderr, "Usage: server [E|D] <local_port> <proxy_host> <proxy_port>\n");
		return -1;
	}
	//local port is port that receives stuff
	//destination port is port to send stuff to
	local_port = argv[2];
	destination_host = argv[3];
	destination_port = argv[4];

	// Using getaddrinfo to obtain the first address to bind to
	struct addrinfo result_hints;
	struct addrinfo *result_list;

	memset(&result_hints, 0, sizeof(struct addrinfo));

	result_hints.ai_family = AF_UNSPEC;
	result_hints.ai_socktype = SOCK_STREAM;
	result_hints.ai_flags = AI_PASSIVE;

	//for connections, use local_port
	result = getaddrinfo(NULL, local_port, &result_hints, &result_list);

	if(result != 0) {
		perror("Cannot obtain address");

		return -1;
	}

	//this is c in Decrypt repeater and a in encrypt repeater
	// Listening socket creation
	int listen_socket;

	for(struct addrinfo *result_curr = result_list; result_curr != NULL; result_curr = result_curr->ai_next) {
		
		// Listening socket creation
		listen_socket = socket(result_curr->ai_family, result_curr->ai_socktype, result_curr->ai_protocol);

		if(listen_socket == -1) {
			continue;
		}

		// Binding to a local address/port
		result = bind(listen_socket, result_curr->ai_addr, result_curr->ai_addrlen);

		if(result == -1) {
			close(listen_socket);
			listen_socket = -1;

			continue;
		}

		print_address_information("Listening in address [%s] port [%s]\n", result_curr->ai_addr, result_curr->ai_addrlen);

		break;
	}

	if(listen_socket == -1) {
		fprintf(stderr, "Not possible to bind to any address/port\n");

		return -1;
	}

	// Listen for connections to a/c

	result = listen(listen_socket, 5);

	if(result == -1) {
		perror("Impossible to listen to connections");

		return -1;
	}

	// Prepare the TLS library

	init_openssl_library();
	tls_context = get_tls_context();

	// Read from client and echo its messages
	int client_socket;
	struct sockaddr_storage client_socket_address;
	socklen_t client_socket_size;

	client_socket_size = sizeof(struct sockaddr_storage);

	while(1) {
		client_socket = accept(listen_socket, (struct sockaddr *) &client_socket_address, &client_socket_size);

		if(client_socket == -1) {
			perror("Cannot accept client");

			return -1;
		}

		// Read from client and echo its messages
		print_address_information("Connection from client from [%s] port [%s]\n", (struct sockaddr *) &client_socket_address, client_socket_size);

		int pid = fork();

		if(pid != 0) {
			// Server executes this
			close(client_socket);
		}
		else {
			// Client executes this
			if(mode == MODE_E) {
				handle_client_encrypt(client_socket);
			}
			else {
				handle_client_decrypt(client_socket);

			}

			close(client_socket);

			// This call is important
			exit(0);
		}
	}

	return 0;
}

int handle_client_encrypt(int client_socket) {
	
	int remote_socket = create_client(destination_host, destination_port);

	//start https handshake 
	SSL *remote_ssl = tls_session_active(remote_socket, tls_context);

	//should it be forward_connection(destination_host, ssl, client_socket)?
	//determine which socket is protected, unprotected
	forward_connection(client_socket, remote_ssl,remote_socket);
	SSL_shutdown(remote_ssl);
	SSL_free(remote_ssl);
	close(client_socket);
	close(remote_socket);

	return 1;

}

//localport will be 9000 for decrypt
//will create connection to http proxy
int handle_client_decrypt(int client_socket) {

	int remote_socket = create_client(destination_host, destination_port);

	//wait for https handshake to complete by calling tls_session_passive() on c socket (localport)
	int pid = fork();

	if(pid != 0) {
		//close client_socket
		close(client_socket);
	}

	else {

		SSL *ssl = tls_session_passive(client_socket, tls_context);	//create ssl box
		//pass client socket and tls context to box.

		// Client executes this
		handle_client(client_socket, ssl);

		forward_connection(client_socket, ssl, remote_socket);
		SSL_shutdown(ssl);
		SSL_free(ssl);	//free memory on exit
		close(client_socket);
		close(remote_socket);

		exit(0);
	}
	return 1;
}

//protected is client, unprotected is destination
int forward_connection(int protected_socket, SSL *protected_ssl, int unprotected_socket) {

	//use select() to forward requests between sockets involved in "E" or "D".
	//add protected socket and unprotected socket into select() call.
	//if protected socket is ready for reading use sslread() to read into buffer,
	//forward to unprotected socket using write();
	int result;
	fd_set descriptor_set;

	while(1){
		FD_ZERO(&descriptor_set);
		FD_SET(0, &descriptor_set);

		//not sure if should be protected_socket or unprotected_socket
		FD_SET(protected_socket, &descriptor_set);

		result = select(MAX(0,protected_socket) + 1, &descriptor_set, NULL, NULL, 0);
		
		if(result == -1) {
			perror("select");
			continue;
		}

		if(FD_ISSET(0, &descriptor_set)) {
			fgets(buffer, BUFFER_SIZE, stdin);

			if(strcmp(buffer, "exit") == 0) {
				break;
			}

			flush_buffer(remote_socket, buffer, strlen(buffer));
		}

		//not sure here 
		if(FD_ISSET(protected_socket, &descriptor_set)) {
			int nread = SSL_read(protected_socket, buffer, BUFFER_SIZE - 1);

			if(nread == 0) {
				break;
			}

			buffer[nread] = '\0';
			//write to unprotected_socket here instead of printing.
			printf("%s", buffer);
		}

		//not really sure here
		if(FD_ISSET(unprotected_socket, &descriptor_set)) {
			int nread = SSL_read(unprotected_socket, buffer, BUFFER_SIZE - 1);

			if(nread == 0) {
				break;
			}

			buffer[nread] = '\0';
			//write to unprotected_socket here instead of printing.
			printf("%s", buffer);
		}







	}
	return 1;
}

void print_address_information(char *template, struct sockaddr *address, int address_size) {
	int result;

	char host[1024];
	char port[16];

	result = getnameinfo(address, address_size, host, 1024, port, 16, NI_NUMERICHOST | NI_NUMERICSERV);

	if(result != 0) {
		perror("Error obtaining information from client");
	}

	printf(template, host, port);
}

int flush_buffer(int socket, char *buffer, int ntowrite) {
	int result;

	int nwritten = 0;

	while(ntowrite > 0) {
		result = write(socket, buffer + nwritten, ntowrite);

		if(result == -1) {
			perror("write");

			return -1;
		}

		nwritten += result;
		ntowrite -= result;
	}

	return nwritten;
}

int flush_buffer_ssl(SSL *ssl, char *buffer, int ntowrite) {
	int result;

	int nwritten = 0;

	while(ntowrite > 0) {
		result = SSL_write(ssl, buffer + nwritten, ntowrite);

		if(result == -1) {
			perror("write");

			return -1;
		}

		nwritten += result;
		ntowrite -= result;
	}

	return nwritten;
}
