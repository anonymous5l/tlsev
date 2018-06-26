#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h> 

#include <openssl/err.h>

#include "tlsclient.h"

SSL_CTX *ctx;

void tlswrite(evutil_socket_t fd, short event, void *arg);
void tlsread(evutil_socket_t fd, short event, void *arg);

SSL_CTX *
init_ssl_ctx(const char *ca, const char *key) {
	SSL_CTX* ctx = NULL;
	EC_KEY *ecdh = NULL;

	assert((ctx = SSL_CTX_new(TLSv1_2_server_method())) != NULL);

	// disable unsafe protocol
	const long flags = SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_SINGLE_DH_USE | SSL_OP_SINGLE_ECDH_USE;

	SSL_CTX_set_options(ctx, flags);
	SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!CAMELLIA:!DES:!MD5:!PSK:!RC4");
	
	assert((ecdh = EC_KEY_new_by_curve_name (NID_X9_62_prime256v1)) != NULL);
	assert(SSL_CTX_set_tmp_ecdh(ctx, ecdh) == 1);
	EC_KEY_free(ecdh);

	assert(SSL_CTX_use_certificate_chain_file(ctx, ca) == 1);
	assert(SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) == 1);
	assert(SSL_CTX_check_private_key(ctx) == 1);

	return ctx;
}

void
tlsclenup(tls_client *client) {
	printf("tlscleanup: %p\n", client);
	event_del(client->ev);
	evutil_closesocket(client->fd);
	SSL_free(client->ssl);
	free(client);
}

void
tlshandle(evutil_socket_t fd, short event, void *arg) {
	if (event & EV_READ) {
		tlsread(fd, event, arg);
	} else if (event & EV_WRITE) {
		tlswrite(fd, event, arg);
	} else {
		tlsclenup((tls_client*)arg);
	}
}

void
tlswrite(evutil_socket_t fd, short event, void *arg) {
	tls_client *client;
	char buffer[BUFFERSIZE];
	int nread = BUFFERSIZE;
	int err;
	int flag;

	flag = EV_ET;
	client = (tls_client*)arg;

	while ((nread = BIO_read(client->wio, buffer, nread)) > 0) {
		assert(send(fd, buffer, nread, 0) == nread);

		if (!SSL_is_init_finished(client->ssl)) {
			err = SSL_accept(client->ssl);
			err = SSL_get_error(client->ssl, err);
		
			switch (err) {
				case SSL_ERROR_WANT_READ:
				case SSL_ERROR_WANT_WRITE:
				case SSL_ERROR_NONE:
					flag |= EV_READ;
					break;
				default:
					printf("SSL: %s\n", ERR_error_string(ERR_get_error(), NULL));
					// read error maybe free tls client
					break;
			}
		}

		flag |= EV_READ;
	}

	// if (nread == -1 && errno != EAGAIN) {
	// 	// read error maybe free tls client
	// 	// server overrload
	// 	tlsclenup(client);
	// } else {
	assert(event_assign(client->ev, client->base, fd, flag, tlshandle, arg) == 0);
	event_add(client->ev, NULL);
	// }
}

void
tlsread(evutil_socket_t fd, short event, void *arg) {
	char buffer[BUFFERSIZE];
	tls_client *client;
	int nread;
	int err;
	int flag;

	flag = EV_ET;
	client = (tls_client*)arg;
	while ((nread = read(fd, buffer, BUFFERSIZE)) > 0) {
		assert(BIO_write(client->rio, buffer, nread) == nread);

		if (!SSL_is_init_finished(client->ssl)) {
			err = SSL_accept(client->ssl);
			err = SSL_get_error(client->ssl, err);
		
			switch (err) {
				case SSL_ERROR_WANT_READ:
				case SSL_ERROR_WANT_WRITE:
				case SSL_ERROR_NONE:
					flag |= EV_WRITE;
					break;
				default:
					printf("SSL: %s\n", ERR_error_string(ERR_get_error(), NULL));
					tlsclenup(client);
					return;
			}
		} else {
			while ((nread = SSL_read(client->ssl, buffer, BUFFERSIZE)) > 0) {
				buffer[nread] = 0;
				printf("RECV: %s\n", buffer);

				SSL_write(client->ssl, buffer, nread);

				flag |= EV_WRITE | EV_READ;
			}
		}
	}

	if (nread == -1 && errno != EAGAIN) {
		// read error maybe free tls client
		tlsclenup(client);
	} else if (nread == 0) {
		// read error maybe free tls client
		tlsclenup(client);
	} else {
		assert(event_assign(client->ev, client->base, fd, flag, tlshandle, arg) == 0);
		event_add(client->ev, NULL);
	}
}

void
tlsaccept(evutil_socket_t fd, short event, void *arg) {
	struct sockaddr_in addr;
	struct event *evaccept;
	struct event *evclient;
	socklen_t size;
	int cfd;
	struct event_base *base;
	SSL *ssl;
	tls_client *client;

	evaccept = (struct event*)arg;
	assert((base = event_get_base(evaccept)) != NULL);

	while ((cfd = accept(fd, (struct sockaddr*)&addr, &size)) > 0) {
		// set to ssl connection
		ssl = SSL_new(ctx);

		if (ssl != NULL) {
			assert(evutil_make_socket_nonblocking(cfd) == 0);

			// alloc tls_client struct
			client = malloc(sizeof(tls_client));
			client->fd = cfd;
			client->rio = BIO_new(BIO_s_mem());
			assert(client->rio != NULL);
			client->wio = BIO_new(BIO_s_mem());
			assert(client->wio != NULL);
			client->ssl = ssl;
			client->base = base;

			SSL_set_bio(client->ssl, client->rio, client->wio);
			SSL_set_accept_state(client->ssl);

			evclient = event_new(base, cfd, EV_READ | EV_ET, tlshandle, client);
			client->ev = evclient;
			event_add(evclient, NULL);

			printf("tlsnew: %p\n", client);
		} else {
			printf("Can't alloc ssl ctx!\n");
		}
	}

	// readd accept event
	event_add(evaccept, NULL);
}

int
main(int argc, char **argv) {
	struct event_base *base;
	struct event *evaccept;
	struct sockaddr_in s_addr;
	evutil_socket_t fd;
	const char *ca;
	const char *key;

	assert((ca = getenv("EVTLS_CA")) != NULL);
	assert((key = getenv("EVTLS_KEY")) != NULL);

	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();

	base = event_base_new();

	ctx = init_ssl_ctx(ca, key);

	fd = socket(PF_INET, SOCK_STREAM, 0);
	assert(fd != -1);

	memset(&s_addr, 0, sizeof(s_addr));
	s_addr.sin_family = PF_INET;
	s_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	s_addr.sin_port = htons(9090);

	assert(evutil_make_listen_socket_reuseable(fd) == 0);
	assert(evutil_make_socket_nonblocking(fd) == 0);

	assert(bind(fd, (struct sockaddr*)&s_addr, sizeof(s_addr)) == 0);
	assert(listen(fd, 1024) == 0);

	evaccept = event_new(base, fd, EV_READ | EV_ET, tlsaccept, NULL);
	assert(event_assign(evaccept, base, fd, EV_READ | EV_ET, tlsaccept, evaccept) == 0);
	event_add(evaccept, NULL);

	printf("tls server running on port %d \n", 9090);

	event_base_dispatch(base);
	event_del(evaccept);
	evutil_closesocket(fd);
	event_base_free(base);
}