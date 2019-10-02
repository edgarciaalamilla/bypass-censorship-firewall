/*
 * Copyright (c) 2018, Hammurabi Mendes.
 * License: BSD 2-clause
 */
#ifndef NETWORKING_H
#define NETWORKING_H

/**
 * Create an accept socket in the specified \p port.
 *
 * @param port Port where the server should run.
 * @return The server socket, or -1 if an error is found -- errno indicate the error.
 */
int create_server(int port);

/**
 * Accept a client in the specified \p accept_socket.
 *
 * @param accept_socket Accept socket used to listen to clients.
 * @return The client socket, or -1 if an error is found -- errno indicate the error.
 */
int accept_client(int accept_socket);

/**
 * Get information about the peer connected to the socket \p socket.
 *
 * @param socket Socket that is connected to the peer we are getting information from.
 * @param host_string Pointer to the character buffer that will hold the hostname.
 * @param host_length Length of the character buffer that will hold the hostname.
 * @param port Pointer to an integer that will contain the port upon return.
 */
void get_peer_information(int socket, char *host_string, int host_length, int *port);

/**
 * Turns socket non-blocking on/off.
 * When non-blocking is on, read and write operations will return error codes instead of blocking.
 * When non-blocking is off... well, it blocks! :)
 *
 * @param socket Socket that will have its non-blocking flag set on/off.
 * @param flag 1 to turn non-blockingness ON; 0 to turn it OFF.
 */
void make_nonblocking(int socket, int flag);

/**
 * Create a connected socket in the specified \p destination and \p port.
 *
 * @param destination Destination where we should connect to.
 * @param port Port where we should connect to.
 * @return The connected socket, or -1 if an error is found -- errno indicate the error.
 */
int create_client(char *destination, char *port);

#endif /* NETWORKING_H */
