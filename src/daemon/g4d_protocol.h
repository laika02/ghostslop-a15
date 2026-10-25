/* Local wire protocol shared by g4sh and g4d. */
#ifndef G4D_PROTOCOL_H
#define G4D_PROTOCOL_H

#include <stdint.h>

#define G4D_PROTO_MAGIC 0x47345348u
#define G4D_PROTO_VERSION 1u
#define G4D_MAX_PAYLOAD 4096u
#define G4D_TERM_MAX 64u
#define G4D_TERMINFO_MAX 256u

enum g4d_message_type {
  G4D_MSG_STDIN = 1,
  G4D_MSG_STDOUT = 2,
  G4D_MSG_RESIZE = 3,
  G4D_MSG_EOF = 4,
};

struct g4d_hello {
  uint32_t magic;
  uint16_t version;
  uint16_t rows;
  uint16_t cols;
  uint16_t xpixel;
  uint16_t ypixel;
  char term[G4D_TERM_MAX];
  char terminfo[G4D_TERMINFO_MAX];
};

struct g4d_frame {
  uint32_t magic;
  uint16_t type;
  uint16_t length;
};

struct g4d_winsize {
  uint16_t rows;
  uint16_t cols;
  uint16_t xpixel;
  uint16_t ypixel;
};

#endif
