#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "base64.h"

int main(void) {
    char * msg = "Hello world! åäö";
    char * enc = b64_encode(msg, strlen(msg));

    char * dec = (char *) malloc(strlen(enc) + 1);
    b64_decode(enc, dec, strlen(enc));

    printf("Enc: %s\n", dec);
}