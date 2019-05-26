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

#define MSG       "Hello from client!"
#define MSG_SIZE  100

#define CLIENT_IDENTITY "Client_identity"
unsigned char preShaedKey[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x06, 0x07, 0x08, 0x09};
size_t pskLen = sizeof(preShaedKey);

unsigned int psk_client_callback(SSL *ssl, const char *hint,
        char *identity, unsigned int max_identity_len,
        unsigned char *psk, unsigned int max_psk_len)
{
	memcpy(identity, CLIENT_IDENTITY, sizeof(CLIENT_IDENTITY));
	memcpy(psk, preShaedKey, pskLen);
	return pskLen;
}

int main(int argc, char const *argv[]) {

    in_addr_t ip;
    int port;
    int sock;
    struct sockaddr_in addr;

    SSL_CTX * ctx = NULL;
    SSL * ssl = NULL;

    switch (argc)
    {
      case 3:
        port = atoi(argv[2]);
        ip = inet_addr(argv[1]);
        break;

      default:
        LOG_ERROR("openssl_tls_client <ip address> <port>\n");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = ip;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
	     LOG_ERROR("Unable to create socket");
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

	SSL_CTX_set_psk_client_callback(ctx, psk_client_callback);

    if ( connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
      LOG_ERROR("Unable to connect");
      exit(EXIT_FAILURE);
    }

    LOG_INFO("Connected to the server");

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    SSL_set_connect_state(ssl);

    if (SSL_do_handshake(ssl) != 1)
    {
      LOG_ERROR("Handshake failed");
      exit(EXIT_FAILURE);
    }

    LOG_INFO("Handshake established");

    char msg[MSG_SIZE] = MSG;
    SSL_write(ssl, msg, sizeof(msg));
    LOG_INFO("Message sent");

    memset(msg, 0, MSG_SIZE);

    SSL_read(ssl, msg, MSG_SIZE);
    printf("received from the server : %s\n", msg);



    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);

    LOG_INFO("Connection closed");

  return 0;
}
