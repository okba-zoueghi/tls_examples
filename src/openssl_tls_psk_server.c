#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl_cipher_suites.h>


#define LOG_ERROR(msg) printf("[ERROR] : %s\n", msg)
#define LOG_INFO(msg) printf("[INFO] : %s\n", msg)

#define MSG       "Hello from server!"
#define MSG_SIZE  100

#define CLIENT_IDENTITY "Client_identity"
unsigned char preShaedKey[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x06, 0x07, 0x08, 0x09};
size_t pskLen = sizeof(preShaedKey);

unsigned int psk_server_callback(SSL *ssl,
                                const char *identity,
                                unsigned char *psk,
                                unsigned int max_psk_len)
{
	if (memcmp(identity, CLIENT_IDENTITY, sizeof(CLIENT_IDENTITY)) != 0)
	{
		LOG_ERROR("No preshared found for the received client_identity");
		return 0;
	}

	memcpy(psk, preShaedKey, pskLen);
	return pskLen;
}


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

    const SSL_METHOD * method = TLSv1_2_method();
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

    if (!SSL_CTX_set_cipher_list(ctx,DHE_PSK_WITH_AES_256_GCM_SHA384 ":"
                                     DHE_PSK_WITH_AES_128_GCM_SHA256 ":"
                                     PSK_WITH_AES_256_CBC_SHA))
    {
      LOG_ERROR("Failed to cipher suites list for TLS v1.2");
      exit(EXIT_FAILURE);
    }

	LOG_INFO("Cipher suites loaded");

	SSL_CTX_set_psk_server_callback(ctx, psk_server_callback);

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
