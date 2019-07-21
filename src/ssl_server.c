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
#include "sodium.h"
#include <security/pam_appl.h>

#include "base64.h"

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

char *rtrim(char *str)
{
    int i;
    const char seps = "\t\n\v\f\r ";
    i = strlen(str) - 1;
    while (i >= 0 && strchr(seps, str[i]) != NULL) {
        str[i] = '\0';
        i--;
    }
    return str;
}

/* Serve the connection -- threadable */
int Servlet(SSL *ssl) {
    char buf[1024] = {0};

    int sd, bytes;
    int retCode = -1;
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

        char *client = NULL;
        char *server = NULL;
        char *ids = NULL;
        char *pids = NULL;
        char *urs = NULL;


        ret = strstr(buf, "\r\n\r\n");
        pair = strtok(ret + 4, "&");

        while(pair) {
            key = (char *)malloc(strlen(pair)+1);
            value = (char *)malloc(strlen(pair)+1);
            sscanf(pair, "%[^=]=%s", key, value);
            if(!strcmp(key, "client")) {
                client = (char *)malloc(strlen(value)+1);
                strcpy(client, value);
            }
            if(!strcmp(key, "server")) {
                server = (char *)malloc(strlen(value)+1);
                strcpy(server, value);
            }
            if(!strcmp(key, "ids")) {
                ids = (char *)malloc(strlen(value)+1);
                strcpy(ids, value);
            }
            if(!strcmp(key, "pids")) {
                pids = (char *)malloc(strlen(value)+1);
                strcpy(pids, value);
            }
            if(!strcmp(key, "urs")) {
                urs = (char *)malloc(strlen(value)+1);
                strcpy(urs, value);
            }
            if(value) free(value);
            if(key) free(key);
            pair = strtok((char *)0, "&");
        }

        unsigned char * decodeClient = (unsigned char *)malloc(strlen(client) + 1);
        b64_decode(client, decodeClient, strlen(client));
        printf("Client: %s\n", decodeClient);

        char *command = NULL;
        pair = strtok(decodeClient, "\r\n");
        while(pair) {
            key = (char *)malloc(strlen(pair)+1);
            value = (char *)malloc(strlen(pair)+1);
            sscanf(pair, "%[^=]=%s", key, value);
            if(!strcmp(key, "cmd")) {
                command = (char *)malloc(strlen(value)+1);
                rtrim(value);
                strcpy(command, value);
            }

            printf("%s = %s\n", key, value);

            if(value) free(value);
            if(key) free(key);
            pair = strtok((char *)0, "&");
        }

        char * message = (char *)malloc(strlen(client) + strlen(server) + 1);
        strcpy(message, client);
        strcat(message, server);

	    printf("MESSAGE(%d): %s\n", strlen(message), message);

        char * idk = "ZIkjsAxCq1oC2Cywhw3NdPZEnWEQlARg_nTDUvpJjuQ";
        unsigned char * decodeIDK = (unsigned char *)malloc(strlen(idk) + 1);
        b64_decode(idk, decodeIDK, strlen(idk));
	
        unsigned char * decodeIDS = (unsigned char *)malloc(strlen(ids) + 1);
        b64_decode(ids, decodeIDS, strlen(ids));
	
        if(crypto_sign_verify_detached(decodeIDS, (unsigned char*) message, (unsigned long long) strlen(message), decodeIDK) != 0) {
            retCode = PAM_AUTH_ERR;
        } else {
            if(command != NULL && !strcmp(command, "ident")) {
                if(1 || !strcmp(idk, idk)) {
                    retCode = PAM_SUCCESS;
                } else {
                    retCode = PAM_USER_UNKNOWN;
                }
            }
        }

        if(client != NULL) {
            printf("Client: %s\n", client);
        }
        if(server != NULL) {
            printf("server: %s\n", server);
        }
        if(ids != NULL) {
            printf("ids: %s\n", ids);
        }
        if(pids != NULL) {
            printf("pids: %s\n", pids);
        }                
        if(urs != NULL) {
            printf("urs: %s\n", urs);
        }

        if (bytes > 0) {
            SSL_write(ssl, ServerResponse, strlen(ServerResponse)); /* send reply */
        } else {
            ERR_print_errors_fp(stderr);
        }
    }
    sd = SSL_get_fd(ssl); /* get socket connection */
    SSL_free(ssl);        /* release SSL state */
    close(sd);            /* close connection */

    return retCode;
}