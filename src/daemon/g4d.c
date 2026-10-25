/* g4d.c — ghostlock root daemon: abstract-socket root shell server.
 *
 * Started by the wq-umh helper (init creds) after a successful root:
 *   /data/local/tmp/a/g4d          (device; self-daemonizes)
 *   /boot/g4d                      (QEMU guest, via fake_sh hook)
 *
 * Listens on @ghostlockd. Per connection, SO_PEERCRED permits UID 0 or
 * 2000/shell, then a fresh PTY shell is bridged using g4d_protocol.h.
 * Build g4d and g4sh from the same source revision because the socket
 * protocol is versioned and both ends must agree.
 */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include "g4d_protocol.h"

#ifndef G4D_NAME
#define G4D_NAME   "ghostlockd"
#endif
#ifndef G4D_PIDF
#define G4D_PIDF   "/data/local/tmp/a/g4d.pid"
#endif
#define G4D_SHELL  "/system/bin/sh"

static int peer_ok(int fd) {
  struct ucred cr;
  socklen_t len = sizeof(cr);
  if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &len) != 0)
    return 0;
  return cr.uid == 0 || cr.uid == 2000;
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

static int recv_hello(int fd, struct g4d_hello *hello) {
  if (!read_all(fd, hello, sizeof(*hello)) ||
      hello->magic != G4D_PROTO_MAGIC ||
      hello->version != G4D_PROTO_VERSION ||
      !memchr(hello->term, '\0', sizeof(hello->term)) ||
      !memchr(hello->terminfo, '\0', sizeof(hello->terminfo)))
    return 0;
  if (!hello->rows)
    hello->rows = 24;
  if (!hello->cols)
    hello->cols = 80;
  return 1;
}

static void send_eof_to_pty(int master) {
  const unsigned char eof = 4;
  (void)write_all(master, &eof, sizeof(eof));
}

/* Bridge framed client input/resize messages and PTY output. */
static void bridge(int cfd, int master, pid_t shell) {
  int client_open = 1;
  unsigned char buf[G4D_MAX_PAYLOAD];
  while (1) {
    struct pollfd pf[2] = {
      { .fd = client_open ? cfd : -1, .events = POLLIN },
      { .fd = master, .events = POLLIN },
    };
    int pr = poll(pf, 2, 1000);
    if (pr < 0) {
      if (errno == EINTR)
        continue;
      break;
    }
    if (waitpid(shell, NULL, WNOHANG) == shell)
      break;
    if (pr == 0)
      continue;

    if (client_open && (pf[0].revents & POLLIN)) {
      struct g4d_frame frame;
      if (!recv_frame(cfd, &frame, buf, sizeof(buf))) {
        send_eof_to_pty(master);
        client_open = 0;
      } else if (frame.type == G4D_MSG_STDIN) {
        if (frame.length && !write_all(master, buf, frame.length))
          break;
      } else if (frame.type == G4D_MSG_RESIZE &&
                 frame.length == sizeof(struct g4d_winsize)) {
        struct g4d_winsize size;
        struct winsize ws;
        memcpy(&size, buf, sizeof(size));
        memset(&ws, 0, sizeof(ws));
        ws.ws_row = size.rows;
        ws.ws_col = size.cols;
        ws.ws_xpixel = size.xpixel;
        ws.ws_ypixel = size.ypixel;
        (void)ioctl(master, TIOCSWINSZ, &ws);
      } else if (frame.type == G4D_MSG_EOF && frame.length == 0) {
        send_eof_to_pty(master);
        client_open = 0;
      } else {
        break;
      }
    }
    if (client_open && !(pf[0].revents & POLLIN) &&
        (pf[0].revents & (POLLHUP | POLLERR | POLLNVAL))) {
      send_eof_to_pty(master);
      client_open = 0;
    }

    if (pf[1].revents & POLLIN) {
      ssize_t n = read(master, buf, sizeof(buf));
      if (n <= 0 || !send_frame(cfd, G4D_MSG_STDOUT, buf, (size_t)n))
        break;
    }
    if (pf[1].revents & (POLLHUP | POLLERR | POLLNVAL))
      break;
  }
}

/* One shell session on its own PTY. Never returns. */
static void session(int cfd) {
  struct g4d_hello hello;
  if (!recv_hello(cfd, &hello))
    _exit(1);

  int master = posix_openpt(O_RDWR | O_NOCTTY);
  if (master < 0)
    _exit(1);
  if (grantpt(master) != 0 || unlockpt(master) != 0)
    _exit(1);
  struct winsize ws = {
    .ws_row = hello.rows,
    .ws_col = hello.cols,
    .ws_xpixel = hello.xpixel,
    .ws_ypixel = hello.ypixel,
  };
  if (ioctl(master, TIOCSWINSZ, &ws) != 0)
    _exit(1);

  char slave[128];
  if (ptsname_r(master, slave, sizeof(slave)) != 0)
    _exit(1);
  pid_t pid = fork();
  if (pid == 0) {
    setsid();
    int sfd = open(slave, O_RDWR);  /* becomes the controlling tty */
    if (sfd < 0)
      _exit(127);
    dup2(sfd, STDIN_FILENO);
    dup2(sfd, STDOUT_FILENO);
    dup2(sfd, STDERR_FILENO);
    if (sfd > STDERR_FILENO)
      close(sfd);
    close(master);
    close(cfd);
    if (hello.term[0])
      setenv("TERM", hello.term, 1);
    if (hello.terminfo[0])
      setenv("TERMINFO", hello.terminfo, 1);
    char *const argv[] = { (char *)"sh", NULL };
    execv(G4D_SHELL, argv);
    _exit(127);
  }
  if (pid < 0)
    _exit(1);
  bridge(cfd, master, pid);
  close(master);
  close(cfd);
  _exit(0);
}

int main(void) {
  /* Daemonize so the UMH caller never blocks. */
  pid_t p = fork();
  if (p < 0)
    return 1;
  if (p > 0) {
    int pf = open(G4D_PIDF, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (pf >= 0) {
      dprintf(pf, "%d\n", p);
      close(pf);
    }
    return 0;
  }
  setsid();
  int null_fd = open("/dev/null", O_RDWR);
  if (null_fd >= 0) {
    dup2(null_fd, STDIN_FILENO);
    dup2(null_fd, STDOUT_FILENO);
    dup2(null_fd, STDERR_FILENO);
    if (null_fd > STDERR_FILENO)
      close(null_fd);
  }
  /* UMH launches g4d through /system/bin/lmkd to pass DEFEX SafePlace;
   * the executable comm starts as lmkd, so set a useful process name. */
  prctl(PR_SET_NAME, "g4d", 0, 0, 0);

  int lfd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (lfd < 0) {
    fprintf(stderr, "g4d: socket: %s\n", strerror(errno));
    _exit(1);
  }
  struct sockaddr_un un;
  memset(&un, 0, sizeof(un));
  un.sun_family = AF_UNIX;
  strcpy(un.sun_path + 1, G4D_NAME);
  socklen_t alen = sizeof(sa_family_t) + 1 + strlen(G4D_NAME);
  if (bind(lfd, (struct sockaddr *)&un, alen) != 0) {
    fprintf(stderr, "g4d: bind @%s: %s\n", G4D_NAME, strerror(errno));
    _exit(1);
  }
  if (listen(lfd, 4) != 0) {
    fprintf(stderr, "g4d: listen: %s\n", strerror(errno));
    _exit(1);
  }

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = SIG_DFL;
  sa.sa_flags = SA_NOCLDWAIT;
  sigaction(SIGCHLD, &sa, NULL);

  for (;;) {
    int cfd = accept(lfd, NULL, NULL);
    if (cfd < 0) {
      if (errno == EINTR)
        continue;
      _exit(1);
    }
    if (!peer_ok(cfd)) {
      close(cfd);
      continue;
    }
    pid_t s = fork();
    if (s == 0) {
      close(lfd);
      session(cfd);
    }
    close(cfd);
  }
}
