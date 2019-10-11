#include "openssl/ssl.h"
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdbool.h>

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

#define PAM_SM_AUTH
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include "ssl_server.h"
#include "google_qrcode.h"

#define MODULE_NAME   "pam_sqrl_login"

#ifndef UNUSED_ATTR
# if __GNUC__ >= 3 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 7)
#  define UNUSED_ATTR __attribute__((__unused__))
# else
#  define UNUSED_ATTR
# endif
#endif

int converse(pam_handle_t *pamh, int nargs,
                    const struct pam_message **message,
                    struct pam_response **response) {
  struct pam_conv *conv;
  int retval = pam_get_item(pamh, PAM_CONV, (void *)&conv);
  if (retval != PAM_SUCCESS) {
    return retval;
  }
  return conv->conv(nargs, message, response, conv->appdata_ptr);
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags UNUSED_ATTR, int argc, const char **argv) {
    char prompt[4000];
    setbuf(stdout, prompt);
    displayQRCode("sqrl://192.168.6.11:8080/sqrl?nut=5hqZKuHyq5t6y2ifoW3wPw", false);
    setbuf(stdout, NULL);

    const struct pam_message msg = {
      .msg_style = PAM_PROMPT_ECHO_ON,
      .msg = prompt
    };
    const struct pam_message *msgs = &msg;
    struct pam_response *resp = NULL;
    int retval = converse(pamh, 1, &msgs, &resp);

    if (retval == PAM_SUCCESS) {
      printf("Response %s", resp->resp);
    }

    SSL_CTX *ctx;
    int server;

    //Only root user have the permission to run the server
    if (!isRoot()) {
        printf("This program must be run as root/sudo user!!");
        exit(0);
    }

    // Initialize the SSL library
    SSL_library_init();

    ctx = InitServerCTX();                        // initialize SSL
    LoadCertificates(ctx, "/home/woden/github/sqrl-libpam/cert.pem", "/home/woden/github/sqrl-libpam/key.pem"); // load certs
    server = OpenListener(8080);         // create server socket

    int retCode = -1;

    while (retCode == -1) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;

        int client = accept(server, (struct sockaddr *)&addr, &len); // accept connection as usual
        printf("Connection: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ssl = SSL_new(ctx);      //get new SSL state with context
        SSL_set_fd(ssl, client); //set connection socket to SSL state
	      retCode = Servlet(ssl);            //service connection
    }

    if(retCode == -1) {
       return PAM_AUTH_ERR;
    }

    sleep(1);

    close(server);     //close server socket
    SSL_CTX_free(ctx); //release context
    return retCode;
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t *pamh UNUSED_ATTR,
                int flags UNUSED_ATTR,
                int argc UNUSED_ATTR,
                const char **argv UNUSED_ATTR) {
  return PAM_SUCCESS;
}

#ifdef PAM_STATIC
struct pam_module _pam_listfile_modstruct = {
  MODULE_NAME,
  pam_sm_authenticate,
  pam_sm_setcred,
  NULL,
  NULL,
  NULL,
  NULL
};
#endif
