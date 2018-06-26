#ifndef _H_TLSCLIENT
#define _H_TLSCLIENT

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

#include <event2/event.h>
#include <event2/util.h>

#include <stdint.h>

#define BUFFERSIZE 1024

typedef struct {
	struct event_base *base;
	struct event *ev;
	evutil_socket_t fd;

	size_t read;

	BIO *wio;
	BIO *rio;

	SSL *ssl;
} tls_client;

#endif
