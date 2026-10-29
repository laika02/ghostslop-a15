/*
 * g4su — small, non-setuid su client for GhostLock's one-boot daemon.
 *
 * The executable's UID is authenticated by g4d with SO_PEERCRED. The daemon
 * starts the requested command as root only for UIDs listed in its current-
 * boot allowlist. This program never changes UID or capabilities itself.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "g4d_protocol.h"

#ifndef G4D_SU_NAME
#define G4D_SU_NAME "ghostlocksu"
#endif

extern char **environ;

static int write_all(int fd, const void *data, size_t length) {
  const unsigned char *p = data;
  while (length) {
    ssize_t n = write(fd, p, length);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      return 0;
    p += n;
    length -= (size_t)n;
  }
  return 1;
}

static int read_all(int fd, void *data, size_t length) {
  unsigned char *p = data;
  while (length) {
    ssize_t n = read(fd, p, length);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      return 0;
    p += n;
    length -= (size_t)n;
  }
  return 1;
}

static int send_frame(int fd, uint16_t type, const void *payload,
                      size_t length) {
  if (length > G4D_MAX_PAYLOAD)
    return 0;
  struct g4d_frame frame = {
    .magic = G4D_PROTO_MAGIC,
    .type = type,
    .length = (uint16_t)length,
  };
  return write_all(fd, &frame, sizeof(frame)) &&
         (!length || write_all(fd, payload, length));
}

static int recv_frame(int fd, struct g4d_frame *frame,
                      void *payload, size_t capacity) {
  if (!read_all(fd, frame, sizeof(*frame)) ||
      frame->magic != G4D_PROTO_MAGIC || frame->length > capacity ||
      frame->length > G4D_MAX_PAYLOAD)
    return 0;
  return !frame->length || read_all(fd, payload, frame->length);
}

static int connect_daemon(void) {
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    return -1;
  struct sockaddr_un un;
  memset(&un, 0, sizeof(un));
  un.sun_family = AF_UNIX;
  strcpy(un.sun_path + 1, G4D_SU_NAME);
  socklen_t alen = sizeof(sa_family_t) + 1 + strlen(G4D_SU_NAME);
  if (connect(fd, (struct sockaddr *)&un, alen) == 0)
    return fd;
  close(fd);
  return -1;
}

static int send_command(int fd, const char *command, uint16_t flags,
                        const char *environment, uint32_t environment_length) {
  size_t length = strlen(command);
  if (!length || length > G4D_SU_MAX_COMMAND)
    return 0;
  struct g4d_su_hello hello = {
    .magic = G4D_PROTO_MAGIC,
    .version = G4D_SU_VERSION,
    .flags = flags,
    .command_length = (uint32_t)length,
    .environment_length = environment_length,
  };
  return write_all(fd, &hello, sizeof(hello)) &&
         write_all(fd, command, length) &&
         (!environment_length ||
          write_all(fd, environment, environment_length));
}

static char *pack_environment(uint32_t *length_out) {
  size_t total = 0;
  for (char **entry = environ; entry && *entry; entry++) {
    size_t length = strlen(*entry) + 1;
    if (length > G4D_SU_MAX_ENV - total) {
      fprintf(stderr, "g4su: environment exceeds %u bytes\n", G4D_SU_MAX_ENV);
      return NULL;
    }
    total += length;
  }
  char *block = malloc(total ? total : 1);
  if (!block)
    return NULL;
  size_t offset = 0;
  for (char **entry = environ; entry && *entry; entry++) {
    size_t length = strlen(*entry) + 1;
    memcpy(block + offset, *entry, length);
    offset += length;
  }
  *length_out = (uint32_t)total;
  return block;
}

static int append_text(char **buffer, size_t *length, size_t *capacity,
                       const char *text) {
  size_t add = strlen(text);
  if (add > G4D_SU_MAX_COMMAND - *length)
    return 0;
  size_t needed = *length + add + 1;
  if (needed > *capacity) {
    size_t next = *capacity ? *capacity : 128;
    while (next < needed)
      next *= 2;
    char *grown = realloc(*buffer, next);
    if (!grown)
      return 0;
    *buffer = grown;
    *capacity = next;
  }
  memcpy(*buffer + *length, text, add);
  *length += add;
  (*buffer)[*length] = '\0';
  return 1;
}

static int valid_shell_path(const char *path) {
  if (!path || path[0] != '/' || strstr(path, ".."))
    return 0;
  for (const unsigned char *p = (const unsigned char *)path; *p; p++) {
    if (!( (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
           (*p >= '0' && *p <= '9') || *p == '/' || *p == '_' ||
           *p == '-' || *p == '.' ))
      return 0;
  }
  return 1;
}

static char *quote_shell_arg(const char *value) {
  size_t length = 2;
  for (const char *p = value; *p; p++)
    length += (*p == '\'') ? 4 : 1;
  char *quoted = malloc(length + 1);
  if (!quoted)
    return NULL;
  char *out = quoted;
  *out++ = '\'';
  for (const char *p = value; *p; p++) {
    if (*p == '\'') {
      memcpy(out, "'\\''", 4);
      out += 4;
    } else {
      *out++ = *p;
    }
  }
  *out++ = '\'';
  *out = '\0';
  return quoted;
}

static int make_command(int argc, char **argv, char **command_out,
                        uint16_t *flags_out) {
  const char *shell = "/system/bin/sh";
  int command_index = -1;
  *flags_out = 0;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-c") == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "g4su: -c requires a command\n");
        return 0;
      }
      command_index = i + 1;
      break;
    }
    if (strcmp(argv[i], "-s") == 0) {
      if (i + 1 >= argc || !valid_shell_path(argv[i + 1])) {
        fprintf(stderr, "g4su: -s requires an absolute shell path\n");
        return 0;
      }
      shell = argv[++i];
    } else if (strcmp(argv[i], "-mm") == 0 ||
               strcmp(argv[i], "-m") == 0 ||
               strcmp(argv[i], "--mount-master") == 0) {
      *flags_out |= G4D_SU_FLAG_MOUNT_MASTER;
    } else if (strcmp(argv[i], "-p") == 0 ||
               strcmp(argv[i], "--preserve-environment") == 0) {
      *flags_out |= G4D_SU_FLAG_PRESERVE_ENV;
    } else if (strcmp(argv[i], "-l") == 0 ||
               strcmp(argv[i], "-") == 0 ||
               strcmp(argv[i], "--") == 0) {
      /* Login mode is not currently implemented. */
    } else if (strcmp(argv[i], "0") == 0 || strcmp(argv[i], "root") == 0) {
      /* Root is the only target identity this manager grants. */
    } else if (argv[i][0] == '-') {
      fprintf(stderr, "g4su: unsupported option: %s\n", argv[i]);
      return 0;
    } else {
      command_index = i;
      break;
    }
  }

  char *body = NULL;
  size_t body_length = 0, body_capacity = 0;
  if (command_index >= 0) {
    for (int i = command_index; i < argc; i++) {
      if (i > command_index && !append_text(&body, &body_length,
                                            &body_capacity, " "))
        goto too_long;
      if (!append_text(&body, &body_length, &body_capacity, argv[i]))
        goto too_long;
    }
  }
  if (body) {
    char *quoted = quote_shell_arg(body);
    free(body);
    if (!quoted)
      return 0;
    size_t needed = strlen(shell) + strlen(quoted) + 10;
    char *command = malloc(needed);
    if (!command) {
      free(quoted);
      return 0;
    }
    snprintf(command, needed, "exec %s -c %s", shell, quoted);
    free(quoted);
    *command_out = command;
    return 1;
  }

  size_t needed = strlen(shell) + 8;
  char *command = malloc(needed);
  if (!command)
    return 0;
  snprintf(command, needed, "exec %s -i", shell);
  *command_out = command;
  return 1;

too_long:
  free(body);
  fprintf(stderr, "g4su: command exceeds %u bytes\n", G4D_SU_MAX_COMMAND);
  return 0;
}

static int run_command(int fd, int interactive) {
  /* g4sh -c feeds `command\nexit\n` through a PTY. A noninteractive su -c
   * inherits that PTY, but must not consume the caller shell's queued `exit`.
   * Keep forwarding real pipe input; leave terminal input queued for caller. */
  int stdin_open = interactive || !isatty(STDIN_FILENO);
  int result = 1;
  unsigned char buffer[G4D_MAX_PAYLOAD];
  while (1) {
    struct pollfd pf[2] = {
      { .fd = stdin_open ? STDIN_FILENO : -1, .events = POLLIN },
      { .fd = fd, .events = POLLIN },
    };
    int pr = poll(pf, 2, -1);
    if (pr < 0) {
      if (errno == EINTR)
        continue;
      break;
    }
    if (stdin_open && (pf[0].revents & (POLLIN | POLLHUP))) {
      ssize_t n = read(STDIN_FILENO, buffer, sizeof(buffer));
      if (n < 0 && (errno == EINTR || errno == EAGAIN)) {
        continue;
      } else if (n > 0) {
        if (!send_frame(fd, G4D_MSG_STDIN, buffer, (size_t)n) &&
            !(pf[1].revents & POLLIN))
          break;
      } else {
        (void)send_frame(fd, G4D_MSG_EOF, NULL, 0);
        stdin_open = 0;
      }
    }
    if (pf[1].revents & POLLIN) {
      struct g4d_frame frame;
      if (!recv_frame(fd, &frame, buffer, sizeof(buffer))) {
        break;
      }
      if (frame.type == G4D_MSG_STDOUT) {
        if (!write_all(STDOUT_FILENO, buffer, frame.length))
          break;
      } else if (frame.type == G4D_MSG_EXIT &&
                 frame.length == sizeof(int32_t)) {
        int32_t code;
        memcpy(&code, buffer, sizeof(code));
        if (code == G4D_SU_ERROR_DENIED) {
          fprintf(stderr, "g4su: this app UID has no current-boot root grant\n");
          result = 1;
        } else if (code == G4D_SU_ERROR_MOUNT_NS) {
          fprintf(stderr, "g4su: could not enter the app mount namespace\n");
          result = 1;
        } else {
          result = code < 0 || code > 255 ? 1 : (int)code;
        }
        break;
      } else {
        fprintf(stderr, "g4su: invalid response from root daemon\n");
        break;
      }
    }
    if (pf[1].revents & (POLLHUP | POLLERR | POLLNVAL))
      break;
  }
  return result;
}

int main(int argc, char **argv) {
  signal(SIGPIPE, SIG_IGN);
  if (argc == 2 && (strcmp(argv[1], "-v") == 0 ||
                    strcmp(argv[1], "-V") == 0 ||
                    strcmp(argv[1], "--version") == 0)) {
    puts("GhostLock su 1.0 (one-boot)");
    return 0;
  }
  if (argc == 2 && (strcmp(argv[1], "-h") == 0 ||
                    strcmp(argv[1], "--help") == 0)) {
    puts("Usage: su [-s shell] [-mm] [-p] [0|root] [-c command]");
    return 0;
  }

  char *command = NULL;
  uint16_t flags = 0;
  if (!make_command(argc, argv, &command, &flags))
    return 2;
  int interactive = strstr(command, " -i") != NULL;
  uint32_t environment_length = 0;
  char *environment = NULL;
  if (flags & G4D_SU_FLAG_PRESERVE_ENV) {
    environment = pack_environment(&environment_length);
    if (!environment) {
      free(command);
      return 1;
    }
  }
  int fd = connect_daemon();
  if (fd < 0) {
    fprintf(stderr, "g4su: root service is unavailable or this app UID has no grant\n");
    free(environment);
    free(command);
    return 1;
  }
  if (!send_command(fd, command, flags, environment, environment_length)) {
    fprintf(stderr, "g4su: could not send command to root service\n");
    close(fd);
    free(environment);
    free(command);
    return 1;
  }
  free(environment);
  free(command);
  int result = run_command(fd, interactive);
  close(fd);
  return result;
}
