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
#include <unistd.h>
#include <fcntl.h>

#include "networking.h"

void reuse_address(int socket);

int create_server(int port) {
	int result;

	struct addrinfo socket_hints;
	struct addrinfo *socket_results;

	memset(&socket_hints, 0, sizeof(struct addrinfo));

	socket_hints.ai_family = AF_UNSPEC;
	socket_hints.ai_socktype = SOCK_STREAM;
	socket_hints.ai_flags = AI_PASSIVE;

	char port_string[16];

	snprintf(port_string, 16, "%d", port);

	result = getaddrinfo(NULL, port_string, &socket_hints, &socket_results);

	if(result != 0) {
		perror("getaddrinfo");

		return -1;
	}

	if(socket_results == NULL) {
		fprintf(stderr, "Cannot find address to bind.");

		return -1;
	}

	int accept_socket = socket(socket_results->ai_family, socket_results->ai_socktype, socket_results->ai_protocol);

	if(accept_socket == -1) {
		perror("socket");

		return -1;
	}

	// Allows a socket in TIME_WAIT to be reused for binding
	// Treats X:Y and Z:Y bindings as different even if Z is 0.0.0.0 (or ::)
	reuse_address(accept_socket);

	result = bind(accept_socket, socket_results->ai_addr, socket_results->ai_addrlen);

	if(result == -1) {
		perror("bind");

		return -1;
	}

	result = listen(accept_socket, 5);

	if(result == -1) {
		perror("listen");

		return -1;
	}

	// Makes the accept socket non-blocking
	// make_nonblocking(accept_socket);

	return accept_socket;
}

int accept_client(int accept_socket) {
	struct sockaddr_storage client_address;
	socklen_t client_length = sizeof(struct sockaddr_storage);

	int client_socket = accept(accept_socket, (struct sockaddr *) &client_address, &client_length);

	// Makes the client socket non-blocking
	// make_nonblocking(client_socket);

	return client_socket;
}

void get_peer_information(int socket, char *host_string, int host_length, int *port) {
	int result;

	struct sockaddr_storage address;
	socklen_t length;

	result = getpeername(socket, (struct sockaddr *) &address, &length);

	if(result == -1) {
		perror("getpeername");

		return;
	}

	char port_string[16];

	result = getnameinfo((struct sockaddr *) &address, length, host_string, host_length, port_string, 16, NI_NUMERICHOST | NI_NUMERICSERV);

	*port = atoi(port_string);

	if(result != 0) {
		perror("getnameinfo");

		return;
	}
}

// Allows a socket in TIME_WAIT to be reused for binding
// Treats X:Y and Z:Y bindings as differents even if Z is 0.0.0.0 (or ::)
void reuse_address(int socket) {
	int option = 1;

	setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(int));
}

// Makes socket non-blocking for reading or writing
void make_nonblocking(int socket, int flag) {
	int options;

	options = fcntl(socket, F_GETFL);

	if(options < 0) {
		perror("fcntl(F_GETFL)");
		exit(EXIT_FAILURE);
	}

	fcntl(socket, F_SETFL, flag ? (options | O_NONBLOCK) : (options & (~O_NONBLOCK)));

	if(options < 0) {
		perror("fcntl(F_SETFL)");
		exit(EXIT_FAILURE);
	}
}

int create_client(char *destination, char *port) {
	int result;
	// Using getaddrinfo to obtain the first address to connect to

	struct addrinfo result_hints;
	struct addrinfo *result_list;

	memset(&result_hints, 0, sizeof(struct addrinfo));

	result_hints.ai_family = AF_UNSPEC;
	result_hints.ai_socktype = SOCK_STREAM;

	result = getaddrinfo(destination, port, &result_hints, &result_list);

	if(result != 0) {
		perror("Cannot obtain address");

		return -1;
	}

	if(result_list == NULL) {
		fprintf(stderr, "No address found");

		return -1;
	}
		// Socket creation

	int remote_socket;

	remote_socket = socket(result_list->ai_family, result_list->ai_socktype, result_list->ai_protocol);

	if(remote_socket == -1) {
		perror("It wasn't possible to create the socket");

		return -1;
	}
	// Connecting to the server
	result = connect(remote_socket, result_list->ai_addr, result_list->ai_addrlen);

	if(result == -1) {
		perror("Cannot connect to the server");

		return -1;
	}
	// 	// Prepare the TLS library

	// init_openssl_library();
	// SSL_CTX *tls_context = get_tls_context_client();	//server needs certificate, client does not111
	// //server sends certificate, client sends key using certificate, server decrypts to get key, then
	// //client and server can use key negotiated by client

	// //load root CA public key, to verify ca
	// //client needs to load less information than the server

	// SSL *remote_ssl = tls_session_active(remote_socket, tls_context);
	// //client creates an encrypting box that is funneling through channel111
	// //operating system creates tcp packdets that are controlled
	

	// char buffer[1024];

	// while(1) {
	// 	printf("Type your message to the server: ");
	// 	fgets(buffer, BUFFER_SIZE, stdin);

	// 	flush_buffer(remote_socket, remote_ssl, buffer, strlen(buffer) + 1);
	// }

	return 0;

}
