/* Local wire protocol shared by g4sh and g4d. */
#ifndef G4D_PROTOCOL_H
#define G4D_PROTOCOL_H

#include <stdint.h>

#define G4D_PROTO_MAGIC 0x47345348u
#define G4D_PROTO_VERSION 1u
#define G4D_SU_VERSION 2u
#define G4D_MAX_PAYLOAD 4096u
#define G4D_SU_MAX_COMMAND 65535u
#define G4D_SU_MAX_ENV 16384u
#define G4D_TERM_MAX 64u
#define G4D_TERMINFO_MAX 256u

enum g4d_message_type {
  G4D_MSG_STDIN = 1,
  G4D_MSG_STDOUT = 2,
  G4D_MSG_RESIZE = 3,
  G4D_MSG_EOF = 4,
  G4D_MSG_EXIT = 5,
  G4D_MSG_STDERR = 6,
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

/* Non-PTY command hello used by the ordinary-app su client. */
struct g4d_su_hello {
  uint32_t magic;
  uint16_t version;
  uint16_t flags;
  uint32_t command_length;
  uint32_t environment_length;
};

#define G4D_SU_FLAG_MOUNT_MASTER 0x0001u
#define G4D_SU_FLAG_PRESERVE_ENV  0x0002u
#define G4D_SU_FLAG_NO_PTY        0x0004u
#define G4D_SU_FLAG_ANDROID_ENV   0x0008u
#define G4D_SU_FLAG_SHELL_CONTEXT 0x0010u
#define G4D_SU_ERROR_DENIED       (-13)
#define G4D_SU_ERROR_MOUNT_NS    (-125)

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
