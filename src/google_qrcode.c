// Copyright 2010 Google Inc.
// Author: Markus Gutschke
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

#define ANSI_RESET        "\x1B[0m"
#define ANSI_BLACKONGREY  "\x1B[30;47;27m"
#define ANSI_WHITE        "\x1B[27m"
#define ANSI_BLACK        "\x1B[7m"
#define UTF8_BOTH         "\xE2\x96\x88"
#define UTF8_TOPHALF      "\xE2\x96\x80"
#define UTF8_BOTTOMHALF   "\xE2\x96\x84"

// Display QR code visually. If not possible, return 0.
int displayQRCode(const char* url, bool utf8) {
  void *qrencode = dlopen("libqrencode.so.2", RTLD_NOW | RTLD_LOCAL);
  if (!qrencode) {
    qrencode = dlopen("libqrencode.so.3", RTLD_NOW | RTLD_LOCAL);
  }
  if (!qrencode) {
    qrencode = dlopen("libqrencode.so.4", RTLD_NOW | RTLD_LOCAL);
  }
  if (!qrencode) {
    qrencode = dlopen("libqrencode.3.dylib", RTLD_NOW | RTLD_LOCAL);
  }
  if (!qrencode) {
    qrencode = dlopen("libqrencode.4.dylib", RTLD_NOW | RTLD_LOCAL);
  }
  if (!qrencode) {
    return 0;
  }
  typedef struct {
    int version;
    int width;
    unsigned char *data;
  } QRcode;
  QRcode *(*QRcode_encodeString8bit)(const char *, int, int) =
      (QRcode *(*)(const char *, int, int))
      dlsym(qrencode, "QRcode_encodeString8bit");
  void (*QRcode_free)(QRcode *qrcode) =
      (void (*)(QRcode *))dlsym(qrencode, "QRcode_free");
  if (!QRcode_encodeString8bit || !QRcode_free) {
    dlclose(qrencode);
    return 0;
  }
  QRcode *qrcode = QRcode_encodeString8bit(url, 0, 1);

  const char *ptr = (char *)qrcode->data;
  // Output QRCode using ANSI colors. Instead of black on white, we
  // output black on grey, as that works independently of whether the
  // user runs their terminal in a black on white or white on black color
  // scheme.
  // But this requires that we print a border around the entire QR Code.
  // Otherwise readers won't be able to recognize it.
  if (!utf8) {
    for (int i = 0; i < 2; ++i) {
      printf(ANSI_BLACKONGREY);
      for (int x = 0; x < qrcode->width + 4; ++x) printf("  ");
      puts(ANSI_RESET);
    }
    for (int y = 0; y < qrcode->width; ++y) {
      printf(ANSI_BLACKONGREY"    ");
      int isBlack = 0;
      for (int x = 0; x < qrcode->width; ++x) {
        if (*ptr++ & 1) {
          if (!isBlack) {
            printf(ANSI_BLACK);
          }
          isBlack = 1;
        } else {
          if (isBlack) {
            printf(ANSI_WHITE);
          }
          isBlack = 0;
        }
        printf("  ");
      }
      if (isBlack) {
        printf(ANSI_WHITE);
      }
      puts("    "ANSI_RESET);
    }
    for (int i = 0; i < 2; ++i) {
      printf(ANSI_BLACKONGREY);
      for (int x = 0; x < qrcode->width + 4; ++x) printf("  ");
      puts(ANSI_RESET);
    }
  } else {
    // Drawing the QRCode with Unicode block elements is desirable as
    // it makes the code much smaller, which is often easier to scan.
    // Unfortunately, many terminal emulators do not display these
    // Unicode characters properly.
    printf(ANSI_BLACKONGREY);
    for (int i = 0; i < qrcode->width + 4; ++i) {
      printf(" ");
    }
    puts(ANSI_RESET);
    for (int y = 0; y < qrcode->width; y += 2) {
      printf(ANSI_BLACKONGREY"  ");
      for (int x = 0; x < qrcode->width; ++x) {
        const int top = qrcode->data[y*qrcode->width + x] & 1;
        int bottom = 0;
        if (y+1 < qrcode->width) {
          bottom = qrcode->data[(y+1)*qrcode->width + x] & 1;
        }
        if (top) {
          if (bottom) {
            printf(UTF8_BOTH);
          } else {
            printf(UTF8_TOPHALF);
          }
        } else {
          if (bottom) {
            printf(UTF8_BOTTOMHALF);
          } else {
            printf(" ");
          }
        }
      }
      puts("  "ANSI_RESET);
    }
    printf(ANSI_BLACKONGREY);
    for (int i = 0; i < qrcode->width + 4; ++i) {
      printf(" ");
    }
    puts(ANSI_RESET);
  }
  QRcode_free(qrcode);
  dlclose(qrencode);
  return 1;
}
