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

	local_port = argv[2];
	destination_host = argv[3];
	destination_port = argv[4];

	struct addrinfo result_hints;
	struct addrinfo *result_list;

	memset(&result_hints, 0, sizeof(struct addrinfo));

	result_hints.ai_family = AF_UNSPEC;
	result_hints.ai_socktype = SOCK_STREAM;
	result_hints.ai_flags = AI_PASSIVE;

	result = getaddrinfo(NULL, local_port, &result_hints, &result_list);

	if(result != 0) {
		perror("Cannot obtain address");

		return -1;
	}

	int listen_socket;

	for(struct addrinfo *result_curr = result_list; result_curr != NULL; result_curr = result_curr->ai_next) {
		
		listen_socket = socket(result_curr->ai_family, result_curr->ai_socktype, result_curr->ai_protocol);

		if(listen_socket == -1) {
			continue;
		}

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

	result = listen(listen_socket, 5);

	if(result == -1) {
		perror("Impossible to listen to connections");

		return -1;
	}

	init_openssl_library();
	tls_context = get_tls_context();

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

		print_address_information("Connection from client from [%s] port [%s]\n", (struct sockaddr *) &client_socket_address, client_socket_size);

		int pid = fork();

		if(pid != 0) {
			close(client_socket);
		}
		else {
			if(mode == MODE_E) {
				handle_client_encrypt(client_socket);
			}
			else {
				handle_client_decrypt(client_socket);
			}
			close(client_socket);

			exit(0);
		}
	}

	return 0;
}

int handle_client_encrypt(int client_socket) {

	SSL *ssl;
	int result;
	int remote_socket;

	if((remote_socket = create_client(destination_host, destination_port)) == -1) {
		perror("create_client");
		return 0;
	}

	if((ssl = tls_session_active(remote_socket, tls_context)) == NULL){
		perror("tls_session_active");
		return 0;
	}

	if((result = SSL_CTX_load_verify_locations(tls_context, SERV_CERTIFICATE, NULL)) == 0){
		perror("SSL");
		return 0;
	}

	if(SSL_get_peer_certificate(ssl) == NULL){
		perror("SSL_get_peer_certificate");
		return 0;
	}

	if(SSL_get_verify_result(ssl) != X509_V_OK){
		perror("SSL_get_verify_result");
		return 0;
	}

	if((result = forward_connection(remote_socket, ssl, client_socket)) == 0){
		perror("forward_connection");
		return 0;
	}

	SSL_shutdown(ssl);
	SSL_free(ssl);

	close(remote_socket);

	return 1;
}

int handle_client_decrypt(int client_socket) {
	int remote_socket;
	SSL *ssl;
	int result;

	if((remote_socket = create_client(destination_host, destination_port)) == -1) {
		perror("create_client");
		return 0;
	}

	if((ssl = tls_session_passive(client_socket, tls_context)) == NULL){
		perror("tls_session_active");
		return 0;
	}

	if((result = forward_connection(client_socket, ssl, remote_socket)) == 0){
		perror("forward_connection");
		return 0;
	}

	SSL_shutdown(ssl);
	SSL_free(ssl);

	close(remote_socket);

	return 1;
}

int forward_connection(int protected_socket, SSL *protected_ssl, int unprotected_socket) {

	int select_result;
	int flush_result;
	fd_set descriptor_set;

	char buffer[BUFFER_SIZE];
	int nread;

	while(1){
		FD_ZERO(&descriptor_set);

		FD_SET(0, &descriptor_set);
		FD_SET(protected_socket, &descriptor_set);
		FD_SET(unprotected_socket, &descriptor_set);

		if((select_result = select(MAX(protected_socket,unprotected_socket) + 1, &descriptor_set, NULL, NULL, 0)) == -1){
			perror("select");
			continue;
		}

		if(FD_ISSET(protected_socket, &descriptor_set)) {
			nread = SSL_read(protected_ssl, buffer, BUFFER_SIZE -1);
			if (nread == 0) break;
			buffer[nread] = '\0';
			if ((flush_result = flush_buffer(unprotected_socket, buffer, nread)) == -1) break;
		}

		if(FD_ISSET(unprotected_socket, &descriptor_set)) {
			nread = read(unprotected_socket, buffer, BUFFER_SIZE - 1);
			if (nread == 0) break;
			buffer[nread] = '\0';
			if ((flush_result = flush_buffer_ssl(protected_ssl, buffer, nread)) == -1) break;
		}

		if(FD_ISSET(0, &descriptor_set)) {
			fgets(buffer, BUFFER_SIZE, stdin);
			if(strcmp(buffer, "exit") == 0) break;
		}
	}

	if(nread == -1){
		perror("read");
		return 0;
	}
	if(flush_result == -1){
		perror("flush_buffer");
		return 0;
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