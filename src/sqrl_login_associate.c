#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"

#include "google_qrcode.h"

#define FAIL -1

// Create the SSL socket and intialize the socket address structure
int OpenListener(int port) {
    int sd;
    struct sockaddr_in addr;

    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("can't bind port");
        abort();
    }

    if (listen(sd, 10) != 0) {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}

int isRoot() {
    if (getuid() != 0) {
        return 0;
    } else {
        return 1;
    }
}

SSL_CTX *InitServerCTX(void) {
    SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();     /* load & register all cryptos, etc. */
    SSL_load_error_strings();         /* load all error messages */
    method = TLSv1_2_server_method(); /* create new server-method instance */
    ctx = SSL_CTX_new(method);        /* create new context from method */
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void LoadCertificates(SSL_CTX *ctx, char *CertFile, char *KeyFile) {
    /* set the local certificate from CertFile */
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

void ShowCerts(SSL *ssl) {
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    if (cert != NULL) {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    } else {
        printf("No certificates.\n");
    }
}

/* Serve the connection -- threadable */
void Servlet(SSL *ssl) {
    char buf[1024] = {0};

    int sd, bytes;
    const char *ServerResponse = "HTTP/1.1 200 OK\r\nContent-Length: 107\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\ndmVyPTENCm51dD01aHFaS3VIeXE1dDZ5Mmlmb1czd1B3DQp0aWY9NQ0KcXJ5PS9zcXJsP251dD01aHFaS3VIeXE1dDZ5Mmlmb1czd1B3DQo";

    if (SSL_accept(ssl) == FAIL) { /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    } else {
        ShowCerts(ssl);                          /* get any certificates */
        bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
        buf[bytes] = '\0';

        char *ret;
        char *pair;
        char *key;
        char *value;

        char *client;
        char *server;
        char *ids;
        char *pids;
        char *urs;


        ret = strstr(buf, "\r\n\r\n");
        pair = strtok(ret + 4, "&");

        while(pair) {
            key = (char *)malloc(strlen(pair)+1);
            value = (char *)malloc(strlen(pair)+1);
            sscanf(pair, "%[^=]=%s", key, value);
            if(!strcmp(key, "client")) {
                client = (char *)malloc(strlen(value)+1);
                strcpy(value, client);
            }
            if(!strcmp(key, "server")) {
                printf("Server: %s\n", value);
            }
            if(!strcmp(key, "ids")) {
                printf("IDS: %s\n", value);
            }
            if(!strcmp(key, "pids")) {
                printf("PIDS: %s\n", value);
            }
            if(!strcmp(key, "urs")) {
                printf("URS: %s\n", value);
            }
            free(value);
            free(key);
            pair = strtok((char *)0, "&");
        }

        if(client) {
            printf("Client: %s\n", client);
            free(client);
        }

        free(ret);
        free(pair);

        if (bytes > 0) {
            SSL_write(ssl, ServerResponse, strlen(ServerResponse)); /* send reply */
        } else {
            ERR_print_errors_fp(stderr);
        }
    }
    sd = SSL_get_fd(ssl); /* get socket connection */
    SSL_free(ssl);        /* release SSL state */
    close(sd);            /* close connection */
}

int main(void) {
    displayQRCode("sqrl://192.168.6.11:8080/sqrl?nut=5hqZKuHyq5t6y2ifoW3wPw");

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
    while (1) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;

        int client = accept(server, (struct sockaddr *)&addr, &len); /* accept connection as usual */
        printf("Connection: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ssl = SSL_new(ctx);      /* get new SSL state with context */
        SSL_set_fd(ssl, client); /* set connection socket to SSL state */
        Servlet(ssl);            /* service connection */
    }
    close(server);     /* close server socket */
    SSL_CTX_free(ctx); /* release context */
    return 0;
}
