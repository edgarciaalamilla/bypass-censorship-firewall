/*
 * Copyright (c) 2018, Hammurabi Mendes.
 * License: BSD 2-clause
 */
#ifndef TLS_H
#define TLS_H

#include <openssl/ssl.h>
#include <openssl/bio.h>

#define SERV_CERTIFICATE "pki_files/serv_certificate.pem"
#define SERV_PRIVKEY "pki_files/serv_privkey.pem"
#define CA_CERTIFICATE "pki_files/ca_certificate.pem"

extern BIO *bio_stderr;

/**
 * Initializes the OpenSSL library.
 */
void init_openssl_library(void);

/**
 * Creates an SSL context, which specifies cyphers, certificates, authorities,
 * and other parameters for an TLS/SSL connection.
 */
SSL_CTX *get_tls_context(void);

/**
 * Given an SSL context, waits for an active party to connect using the TLS/SSL protocol.
 *
 * @param socket Connected socket on the server side.
 * @param context SSL context generated previously.
 *
 * @return An SSL stream that can be read/written with SSL_read/SSL_write.
 */
SSL *tls_session_passive(int socket, SSL_CTX *context);

/**
 * Given an SSL context, connects to a server using the TLS/SSL protocol.
 *
 * @param socket Connected socket on the client side.
 * @param context SSL context generated previously.
 *
 * @return An SSL stream that can be read/written with SSL_read/SSL_write.
 */
SSL *tls_session_active(int socket, SSL_CTX *context);

#endif /* TLS_H */
