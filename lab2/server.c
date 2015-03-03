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


static int init_tcp_listen_socket(int port)
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


/* Check that the common name and email matches the host name and email */
void verify_client_cert(ssl, host, email)
  SSL *ssl;
  char *host;
  char *email;
  {
    X509 *peer;
    char peer_CN[256];
    char peer_EM[256];

    if(SSL_get_verify_result(ssl) != X509_V_OK){
      berr_exit(FMT_NO_VERIFY);
    }

    /* Check the common name */
    peer = SSL_get_peer_certificate(ssl);
    X509_NAME_get_text_by_NID(X509_get_subject_name(peer),
      NID_commonName, peer_CN, 256);
  
    if(strcasecmp(peer_CN, host))
    err_exit(FMT_CN_MISMATCH);

    X509_NAME_get_text_by_NID(X509_get_subject_name(peer),
      NID_pkcs9_emailAddress, peer_EM, 256);
  
    if(strcasecmp(peer_EM, email))
    err_exit(FMT_EMAIL_MISMATCH);  

    // Certificate is valid. Print CN & email address
    printf(FMT_OUTPUT, peer_CN, peer_EM); 

  }


static void serve_request(SSL * ssl, char *answer)
{
	int len;
	char buf[256];

    verify_client_cert(ssl, EXPECTED_HOST_NAME, EXPECTED_CLIENT_EMAIL);
    	
	len = SSL_read(ssl, buf, 255);
	if (len < 0)
		berr_exit("SSL read\n");
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

static void clean_up(int s, int sock, SSL * ssl)
{
	int r = SSL_shutdown(ssl);
	if (!r) {
		/* If we called SSL_shutdown() first then
		   we always get return value of '0'. In
		   this case, try again, but first send a
		   TCP FIN to trigger the other side's
		   close_notify 
			SHUT_WR => Shutdown write direction.
		   */
		shutdown(s, SHUT_WR);
		r = SSL_shutdown(ssl);
	}

	if (r != 1) {
		err_exit(FMT_INCOMPLETE_CLOSE);
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
	char *answer = "42";

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

	// client test
	//int r = SSL_CTX_set_cipher_list(ctx, "ALL:!SHA1");
	

	// Configure SSL server to ask for client certificate.
	SSL_CTX_set_verify(ctx,
	  SSL_VERIFY_PEER|SSL_VERIFY_CLIENT_ONCE|SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
      NULL);

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

			serve_request(ssl, answer);

			clean_up(s, sock, ssl);
			return 0;
		}
	}

	close(sock);
	return 1;
}
