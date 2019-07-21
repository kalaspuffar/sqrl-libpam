int OpenListener(int port);
int isRoot();
SSL_CTX *InitServerCTX(void);
void LoadCertificates(SSL_CTX *ctx, char *CertFile, char *KeyFile);
void ShowCerts(SSL *ssl);
int Servlet(SSL *ssl);
