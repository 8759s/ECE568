#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include "common.h"

#define PORT 8765

/* use these strings to tell the marker what is happening */
#define FMT_ACCEPT_ERR "ECE568-SERVER: SSL accept error\n"
#define FMT_CLIENT_INFO "ECE568-SERVER: %s %s\n"
#define FMT_OUTPUT "ECE568-SERVER: %s %s\n"
#define FMT_INCOMPLETE_CLOSE "ECE568-SERVER: Incomplete shutdown\n"

#define PASSWORD "password"
#define KEY_FILE_PATH "bob.pem"
#define EXPECTED_HOST_NAME "Alice's client"
#define EXPECTED_CLIENT_EMAIL "ece568alice@ecf.utoronto.ca"


int init_tcp_listen_socket(int port)
{
	struct sockaddr_in sin;
	int sock, val = 1;

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		close(sock);
		exit(0);
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);

	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

	if (bind(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		perror("bind");
		close(sock);
		exit(0);
	}

	if (listen(sock, 5) < 0) {
		perror("listen");
		close(sock);
		exit(0);
	}
	return sock;
}

void serve_request(SSL * ssl)
{

	int len;
	char buf[256];
	char *answer = "42";

  //check_cert(ssl, EXPECTED_HOST_NAME, EXPECTED_CLIENT_EMAIL);

	len = SSL_read(ssl, buf, 255);

	if (len < 0)
		berr_exit("SSL gets\n");
	buf[len] = '\0';

	printf(FMT_OUTPUT, buf, answer);

	len = strlen(answer);
	int r = SSL_write(ssl, answer, len);
	switch (SSL_get_error(ssl, r)) {
	case SSL_ERROR_NONE:
		if (len != r)
			err_exit("Incomplete write!");
		break;
	default:
		berr_exit("SSL write problem");
	}

}

void clean_up(int s, int sock, SSL * ssl)
{

	int r = SSL_shutdown(ssl);
	if (!r) {
		/* If we called SSL_shutdown() first then
		   we always get return value of '0'. In
		   this case, try again, but first send a
		   TCP FIN to trigger the other side's
		   close_notify */
		shutdown(s, 1);
		r = SSL_shutdown(ssl);
	}

	switch (r) {
	case 1:
		break;		/* Success */
	case 0:
	case -1:
	default:
		berr_exit("Shutdown failed");
	}

	SSL_free(ssl);
	close(sock);
	close(s);
}


int main(int argc, char **argv)
{
	int s, sock;
	pid_t pid;
	int port = PORT;

	/*Parse command line arguments */

	switch (argc) {
	case 1:
		break;
	case 2:
		port = atoi(argv[1]);
		if (port < 1 || port > 65535) {
			fprintf(stderr, "invalid port number");
			exit(0);
		}
		break;
	default:
		printf("Usage: %s port\n", argv[0]);
		exit(0);
	}

	sock = init_tcp_listen_socket(port);
	SSL_CTX *ctx = initialize_ctx(KEY_FILE_PATH, PASSWORD);

	// reap child zombie processes after handling request
	if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) {
		perror(0);
		exit(0);
	}

	while (1) {

		if ((s = accept(sock, NULL, 0)) < 0) {
			perror("accept");
			close(sock);
			close(s);
			exit(0);
		}

		/*fork a child to handle the connection */

		if ((pid = fork())) {
			close(s);
		} else {
			/*Child code */

			BIO *sbio = BIO_new_socket(s, BIO_NOCLOSE);
			SSL *ssl = SSL_new(ctx);
			SSL_set_bio(ssl, sbio, sbio);

			if ((SSL_accept(ssl) <= 0))
				berr_exit("SSL accept error");

			serve_request(ssl);

			clean_up(s, sock, ssl);

			return 0;
		}
	}

	close(sock);
	return 1;
}
