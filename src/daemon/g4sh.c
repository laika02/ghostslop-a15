/* g4sh.c — terminal-aware client for the ghostlock root daemon (g4d).
 *
 *   g4sh              interactive root shell
 *   g4sh -c "id"      run one command, print its output, exit
 *
 * Connects to the abstract unix socket @ghostlockd. Terminal metadata,
 * resize events, stdin, and stdout use the framed protocol in g4d_protocol.h.
 */
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <termios.h>
#include <unistd.h>

#include "g4d_protocol.h"

#ifndef G4D_NAME
#define G4D_NAME "ghostlockd"
#endif

static volatile sig_atomic_t resize_pending;

static void on_sigwinch(int signo) {
  (void)signo;
  resize_pending = 1;
}

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
  struct g4d_frame frame = {
    .magic = G4D_PROTO_MAGIC,
    .type = type,
    .length = (uint16_t)length,
  };
  return length <= G4D_MAX_PAYLOAD &&
         write_all(fd, &frame, sizeof(frame)) &&
         (!length || write_all(fd, payload, length));
}

static int recv_frame(int fd, struct g4d_frame *frame,
                      void *payload, size_t capacity) {
  if (!read_all(fd, frame, sizeof(*frame)) ||
      frame->magic != G4D_PROTO_MAGIC ||
      frame->length > capacity || frame->length > G4D_MAX_PAYLOAD)
    return 0;
  return !frame->length || read_all(fd, payload, frame->length);
}

static int g4d_connect(void) {
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    return -1;
  struct sockaddr_un un;
  memset(&un, 0, sizeof(un));
  un.sun_family = AF_UNIX;
  strcpy(un.sun_path + 1, G4D_NAME);
  socklen_t alen = sizeof(sa_family_t) + 1 + strlen(G4D_NAME);
  /* The daemon may still be starting when the harness calls. */
  for (int t = 0; t < 10; t++) {
    if (connect(fd, (struct sockaddr *)&un, alen) == 0)
      return fd;
    usleep(200000);
  }
  close(fd);
  return -1;
}

static void fill_winsize(struct g4d_winsize *ws) {
  struct winsize local;
  memset(ws, 0, sizeof(*ws));
  if (ioctl(STDIN_FILENO, TIOCGWINSZ, &local) == 0) {
    ws->rows = local.ws_row;
    ws->cols = local.ws_col;
    ws->xpixel = local.ws_xpixel;
    ws->ypixel = local.ws_ypixel;
  }
  if (!ws->rows)
    ws->rows = 24;
  if (!ws->cols)
    ws->cols = 80;
}

static int send_hello(int fd) {
  struct g4d_hello hello;
  struct g4d_winsize ws;
  memset(&hello, 0, sizeof(hello));
  fill_winsize(&ws);
  hello.magic = G4D_PROTO_MAGIC;
  hello.version = G4D_PROTO_VERSION;
  hello.rows = ws.rows;
  hello.cols = ws.cols;
  hello.xpixel = ws.xpixel;
  hello.ypixel = ws.ypixel;

  const char *term = getenv("TERM");
  if (!term || !*term)
    term = "xterm-256color";
  snprintf(hello.term, sizeof(hello.term), "%s", term);
  const char *terminfo = getenv("TERMINFO");
  if (terminfo)
    snprintf(hello.terminfo, sizeof(hello.terminfo), "%s", terminfo);
  return write_all(fd, &hello, sizeof(hello));
}

static int send_input(int fd, const void *data, size_t length) {
  const unsigned char *p = data;
  while (length) {
    size_t chunk = length > G4D_MAX_PAYLOAD ? G4D_MAX_PAYLOAD : length;
    if (!send_frame(fd, G4D_MSG_STDIN, p, chunk))
      return 0;
    p += chunk;
    length -= chunk;
  }
  return 1;
}

static int run_command(int fd, const char *command) {
  size_t length = strlen(command);
  if (length > SIZE_MAX - 6)
    return 1;
  char *input = malloc(length + 6);
  if (!input)
    return 1;
  memcpy(input, command, length);
  memcpy(input + length, "\nexit\n", 6);
  int ok = send_input(fd, input, length + 6) &&
           send_frame(fd, G4D_MSG_EOF, NULL, 0);
  free(input);
  if (!ok)
    return 1;

  unsigned char buf[G4D_MAX_PAYLOAD];
  struct g4d_frame frame;
  while (recv_frame(fd, &frame, buf, sizeof(buf))) {
    if (frame.type == G4D_MSG_STDOUT) {
      if (!write_all(STDOUT_FILENO, buf, frame.length))
        break;
    } else if (frame.type == G4D_MSG_EOF) {
      break;
    } else {
      fprintf(stderr, "g4sh: invalid response frame type %u\n", frame.type);
      break;
    }
  }
  return 0;
}

int main(int argc, char **argv) {
  int fd = g4d_connect();
  if (fd < 0) {
    fprintf(stderr, "g4sh: g4d not reachable (@%s): %s\n", G4D_NAME,
            strerror(errno));
    return 1;
  }
  if (!send_hello(fd)) {
    fprintf(stderr, "g4sh: failed to send terminal metadata: %s\n",
            strerror(errno));
    close(fd);
    return 1;
  }

  if (argc >= 3 && strcmp(argv[1], "-c") == 0) {
    int rc = run_command(fd, argv[2]);
    close(fd);
    return rc;
  }

  struct termios orig;
  int raw = isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &orig) == 0;
  if (raw) {
    struct termios t = orig;
    cfmakeraw(&t);
    if (tcsetattr(STDIN_FILENO, TCSANOW, &t) != 0)
      raw = 0;
  }

  struct sigaction sa, old_sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = on_sigwinch;
  sigemptyset(&sa.sa_mask);
  int have_signal = sigaction(SIGWINCH, &sa, &old_sa) == 0;

  int stdin_open = 1;
  int done = 0;
  unsigned char buf[G4D_MAX_PAYLOAD];
  while (!done) {
    if (resize_pending) {
      resize_pending = 0;
      struct g4d_winsize ws;
      fill_winsize(&ws);
      if (!send_frame(fd, G4D_MSG_RESIZE, &ws, sizeof(ws)))
        break;
    }

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
    if (stdin_open && (pf[0].revents & (POLLIN | POLLHUP | POLLERR))) {
      ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
      if (n <= 0) {
        send_frame(fd, G4D_MSG_EOF, NULL, 0);
        stdin_open = 0;
      } else if (!send_input(fd, buf, (size_t)n)) {
        break;
      }
    }
    if (pf[1].revents & (POLLIN | POLLHUP | POLLERR)) {
      struct g4d_frame frame;
      if (!recv_frame(fd, &frame, buf, sizeof(buf))) {
        done = 1;
      } else if (frame.type == G4D_MSG_STDOUT) {
        if (!write_all(STDOUT_FILENO, buf, frame.length))
          done = 1;
      } else if (frame.type == G4D_MSG_EOF) {
        done = 1;
      } else {
        fprintf(stderr, "g4sh: invalid response frame type %u\n",
                frame.type);
        done = 1;
      }
    }
  }

  if (have_signal)
    sigaction(SIGWINCH, &old_sa, NULL);
  if (raw)
    tcsetattr(STDIN_FILENO, TCSANOW, &orig);
  close(fd);
  return 0;
}
