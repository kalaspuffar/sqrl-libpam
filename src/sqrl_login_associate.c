#include "openssl/ssl.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdbool.h>

#include "ssl_server.h"
#include "google_qrcode.h"

int main(void) {
    setbuf(stdout, NULL);
    displayQRCode("sqrl://192.168.6.11:8080/sqrl?nut=5hqZKuHyq5t6y2ifoW3wPw", true);

    SSL_CTX *ctx;
    int server;

    //Only root user have the permission to run the server
    if (!isRoot()) {
        printf("This program must be run as root/sudo user!!");
        exit(0);
    }

    // Initialize the SSL library
    SSL_library_init();

    ctx = InitServerCTX();                        /* initialize SSL */
    LoadCertificates(ctx, "cert.pem", "key.pem"); /* load certs */
    server = OpenListener(8080);         /* create server socket */

    int retCode = -1;

    while (retCode == -1) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;

        int client = accept(server, (struct sockaddr *)&addr, &len); /* accept connection as usual */
        printf("Connection: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ssl = SSL_new(ctx);      /* get new SSL state with context */
        SSL_set_fd(ssl, client); /* set connection socket to SSL state */
        retCode = Servlet(ssl);            /* service connection */
    }

    sleep(1);

    close(server);     /* close server socket */
    SSL_CTX_free(ctx); /* release context */
    return retCode;
}
