/*
 * Copyright (c) 2018, Hammurabi Mendes.
 * License: BSD 2-clause
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>

#include "tls.h"

int get_serv_certificate_password(char *buffer, int size, int rwflag, void *userdata);

void init_openssl_library() {
	SSL_library_init();
	SSL_load_error_strings();
}

SSL_CTX *get_tls_context(void) {
	SSL_CTX *context;

	context = SSL_CTX_new(SSLv23_method());

	if(SSL_CTX_use_certificate_chain_file(context, SERV_CERTIFICATE) != 1) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	SSL_CTX_set_default_passwd_cb(context, get_serv_certificate_password);

	if(SSL_CTX_use_PrivateKey_file(context, SERV_PRIVKEY, SSL_FILETYPE_PEM) != 1) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	if(SSL_CTX_load_verify_locations(context, CA_CERTIFICATE, NULL) != 1) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	return context;
}

SSL *tls_session_passive(int socket, SSL_CTX *context) {
	SSL *ssl = SSL_new(context);
	BIO *bio_socket = BIO_new_socket(socket, BIO_NOCLOSE);

	SSL_set_bio(ssl, bio_socket, bio_socket);

	if(SSL_accept(ssl) != 1) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	return ssl;
}

SSL *tls_session_active(int socket, SSL_CTX *context) {
	SSL *ssl = SSL_new(context);
	BIO *bio_socket = BIO_new_socket(socket, BIO_NOCLOSE);

	SSL_set_bio(ssl, bio_socket, bio_socket);

	if(SSL_connect(ssl) != 1) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	return ssl;
}

int get_serv_certificate_password(char *buffer, int size, int rwflag, void *userdata) {
	fputs("Type server's certificate private key password: ", stdout);
	fgets(buffer, size, stdin);

	int last_character_position = strlen(buffer) - 1;

	if(buffer[last_character_position] == '\n') {
		buffer[last_character_position] = '\0';
	}

	return strlen(buffer);
}
