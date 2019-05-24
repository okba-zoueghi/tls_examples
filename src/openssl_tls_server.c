#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl_cipher_suites.h>

/*
 *  ca.cert.pem : root certificate authority certificate
 *  server.chain.cert.pem : server certificate + intermediate certificate authority certificate
 *  server.key.pem : server private key
*/

#define LOG_ERROR(msg) printf("[ERROR] : %s\n", msg)
#define LOG_INFO(msg) printf("[INFO] : %s\n", msg)

#define CHAIN_OF_TRUST_CERT       "../certificates/ca.cert.pem"
#define CERTIFICATE_FILE_PATH     "../certificates/server.chain.cert.pem"
#define PRIVATE_KEY_FILE_PATH     "../keys/server.key.pem"

#define MSG       "Hello from server!"
#define MSG_SIZE  100

int main(int argc, char const *argv[]) {

    int port;
    int sock;
    struct sockaddr_in addr;


    SSL_CTX * ctx = NULL;
    SSL * ssl = NULL;

    switch (argc)
    {
      case 2:
        port = atoi(argv[1]);
        break;

      default:
        printf("openssl_tls_server <port>\n");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (socket < 0)
    {
	     LOG_ERROR("Unable to create socket");
	     exit(EXIT_FAILURE);
    }

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
	     LOG_ERROR("Unable to bind");
	     exit(EXIT_FAILURE);
    }

    if (listen(sock, 1) < 0)
    {
	     LOG_ERROR("Unable to listen");
	     exit(EXIT_FAILURE);
    }

    const SSL_METHOD * method = TLS_method();
    if (!method)
    {
      LOG_ERROR("Failed to create method");
      exit(EXIT_FAILURE);
    }

    ctx = SSL_CTX_new(method);
    if (!ctx)
    {
      LOG_ERROR("Failed to create context");
      exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_set_min_proto_version(ctx,TLS1_2_VERSION))
    {
      LOG_ERROR("Failed to set min version");
      exit(EXIT_FAILURE);
    }

    LOG_INFO("TLS min version set to v1.2");

    if (!SSL_CTX_set_max_proto_version(ctx,TLS1_3_VERSION))
    {
      LOG_ERROR("Failed to set max version");
      exit(EXIT_FAILURE);
    }

    LOG_INFO("TLS max version set to v1.3");

    if (!SSL_CTX_set_cipher_list(ctx,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 ":"
                                     TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ":"
                                     TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384))
    {
      LOG_ERROR("Failed to cipher suites list for TLS v1.2");
      exit(EXIT_FAILURE);
    }

    LOG_INFO("TLS v1.2 cipher suites set");

    if (!SSL_CTX_set_ciphersuites(ctx,TLS_AES_128_GCM_SHA256 ":"
                                      TLS_AES_256_GCM_SHA384 ":"
                                      TLS_CHACHA20_POLY1305_SHA256))
    {
      LOG_ERROR("Failed to cipher suites list for TLS v1.3");
      exit(EXIT_FAILURE);
    }

    LOG_INFO("TLS v1.3 cipher suites set");

    if (SSL_CTX_use_certificate_chain_file(ctx, CERTIFICATE_FILE_PATH) <= 0)
    {
      LOG_ERROR("Failed to load the certificate");
      exit(EXIT_FAILURE);
    }

    LOG_INFO("Server certificate chain loaded");

    if (SSL_CTX_use_PrivateKey_file(ctx, PRIVATE_KEY_FILE_PATH, SSL_FILETYPE_PEM) <= 0) {
      LOG_ERROR("Failed to load the private key");
      exit(EXIT_FAILURE);
    }

    LOG_INFO("Server private key loaded");

    SSL_CTX_load_verify_locations(ctx, CHAIN_OF_TRUST_CERT, NULL);
    LOG_INFO("Chain of trust certificate loaded");


    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    while (1)
    {
      struct sockaddr_in addr;
      unsigned int len = sizeof(addr);
      char recv_msg[MSG_SIZE] = {0};

      LOG_INFO("Waiting for connection ...");
      int client_socket = accept(sock, (struct sockaddr*)&addr, &len);
      if (client_socket < 0)
      {
        LOG_ERROR("Failed to accept");
      }

      ssl = SSL_new(ctx);
      SSL_set_fd(ssl, client_socket);
      SSL_set_accept_state(ssl);

      if (SSL_do_handshake(ssl) != 1)
      {
        LOG_ERROR("Handshake failed");
        exit(EXIT_FAILURE);
      }

      LOG_INFO("Handshake established");

      int msgSz = SSL_read(ssl, recv_msg, 100);
      printf("Message received from client : %s\n", recv_msg);

      memset(recv_msg, 0, MSG_SIZE);
      memcpy(recv_msg, MSG, sizeof(MSG));
      SSL_write(ssl, recv_msg, sizeof(MSG));

      SSL_free(ssl);
      close(client_socket);

      LOG_INFO("Connection closed");
    }


  close(sock);
  SSL_CTX_free(ctx);

  return 0;
}
