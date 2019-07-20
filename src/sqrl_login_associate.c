# #include <openssl/applink.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "google_qrcode.h"

void InitializeSSL()
{
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
}

void DestroySSL()
{
    ERR_free_strings();
    EVP_cleanup();
}

void ShutdownSSL()
{
    SSL_shutdown(cSSL);
    SSL_free(cSSL);
}

int main(void) {
  displayQRCode("sqrl://www.grc.com/sqrl?nut=oEQvS2meLFTjTG36nCaw6w");


  int sockfd, newsockfd;
  SSL_CTX *sslctx;
SSL *cSSL;

InitializeSSL();
sockfd = socket(AF_INET, SOCK_STREAM, 0);
if (sockfd< 0)
{
    //Log and Error
    return;
}
struct sockaddr_in saiServerAddress;
bzero((char *) &saiServerAddress, sizeof(saiServerAddress));
saiServerAddress.sin_family = AF_INET;
saiServerAddress.sin_addr.s_addr = serv_addr;
saiServerAddress.sin_port = htons(8080);

bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr));

listen(sockfd,5);
newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);

sslctx = SSL_CTX_new( SSLv23_server_method());
SSL_CTX_set_options(sslctx, SSL_OP_SINGLE_DH_USE);
int use_cert = SSL_CTX_use_certificate_file(sslctx, "/key.pem" , SSL_FILETYPE_PEM);

int use_prv = SSL_CTX_use_PrivateKey_file(sslctx, "/key.pem", SSL_FILETYPE_PEM);

cSSL = SSL_new(sslctx);
SSL_set_fd(cSSL, newsockfd );
//Here is the SSL Accept portion.  Now all reads and writes must use SSL
ssl_err = SSL_accept(cSSL);
if(ssl_err <= 0)
{
    //Error occurred, log and close down ssl
    ShutdownSSL();
}

SSL_read(cSSL, (char *) charBuffer, nBytesToRead);
SSL_write(cSSL, "Hi :3\n", 6);

  return 0;
}
