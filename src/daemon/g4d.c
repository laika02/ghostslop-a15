#define _GNU_SOURCE
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
#include <sched.h>
#include <signal.h>
#include <stdint.h>
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
#include <time.h>
#include <termios.h>
#include <unistd.h>

#include "g4d_protocol.h"

#ifndef G4D_NAME
#define G4D_NAME   "ghostlockd"
#endif
#ifndef G4D_SU_NAME
#define G4D_SU_NAME "ghostlocksu"
#endif
#ifndef G4D_PIDF
#define G4D_PIDF   "/data/local/tmp/a/g4d.pid"
#endif
#ifndef G4D_ALLOW_FILE
#define G4D_ALLOW_FILE "/dev/ghostlock-g4d.allow"
#endif
#define G4D_SHELL  "/system/bin/sh"

static int read_all(int fd, void *data, size_t length);

static int allowed_by_file(uid_t uid) {
  FILE *boot_file = fopen("/proc/sys/kernel/random/boot_id", "r");
  if (!boot_file)
    return 0;
  char boot_id[64];
  if (!fgets(boot_id, sizeof(boot_id), boot_file)) {
    fclose(boot_file);
    return 0;
  }
  fclose(boot_file);
  boot_id[strcspn(boot_id, "\r\n")] = '\0';
  if (strlen(boot_id) != 36)
    return 0;

  int fd = open(G4D_ALLOW_FILE, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0)
    return 0;
  struct stat st;
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != 0 ||
      (st.st_mode & 077) != 0 || st.st_size > 131072) {
    close(fd);
    return 0;
  }
  FILE *fp = fdopen(fd, "r");
  if (!fp) {
    close(fd);
    return 0;
  }

  char line[96];
  int ok = 0;
  if (!fgets(line, sizeof(line), fp))
    goto out;
  line[strcspn(line, "\r\n")] = '\0';
  if (strncmp(line, "boot_id=", 8) != 0 || strcmp(line + 8, boot_id) != 0)
    goto out;

  while (fgets(line, sizeof(line), fp)) {
    char *end = NULL;
    errno = 0;
    unsigned long value = strtoul(line, &end, 10);
    if (errno || end == line || value > UINT32_MAX ||
        (*end != '\n' && *end != '\r' && *end != '\0'))
      break;
    if ((uid_t)value == uid) {
      ok = 1;
      break;
    }
  }
out:
  fclose(fp);
  return ok;
}

static int peer_ok(int fd, struct ucred *cr) {
  socklen_t len = sizeof(*cr);
  if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, cr, &len) != 0)
    return 0;
  return cr->uid == 0 || cr->uid == 2000 || allowed_by_file(cr->uid);
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

static int recv_hello(int fd, struct g4d_hello *hello,
                      const unsigned char prefix[6]) {
  memcpy(hello, prefix, 6);
  if (!read_all(fd, (unsigned char *)hello + 6, sizeof(*hello) - 6) ||
      hello->magic != G4D_PROTO_MAGIC || hello->version != G4D_PROTO_VERSION ||
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
static void session(int cfd, const unsigned char prefix[6]) {
  struct g4d_hello hello;
  if (!recv_hello(cfd, &hello, prefix))
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
    signal(SIGPIPE, SIG_DFL);
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

/* One su -c command on a PTY, with a framed stdin stream and exit status. */
static void session_su(int cfd, const unsigned char prefix[6], pid_t peer_pid) {
  struct g4d_su_hello hello;
  memcpy(&hello, prefix, 6);
  if (!read_all(cfd, (unsigned char *)&hello + 6, sizeof(hello) - 6) ||
      hello.magic != G4D_PROTO_MAGIC || hello.version != G4D_SU_VERSION ||
      (hello.flags & ~(G4D_SU_FLAG_MOUNT_MASTER | G4D_SU_FLAG_PRESERVE_ENV)) != 0 ||
      hello.command_length == 0 ||
      hello.command_length > G4D_SU_MAX_COMMAND ||
      hello.environment_length > G4D_SU_MAX_ENV ||
      (!(hello.flags & G4D_SU_FLAG_PRESERVE_ENV) && hello.environment_length != 0))
    _exit(1);

  char *command = malloc((size_t)hello.command_length + 1);
  if (!command || !read_all(cfd, command, hello.command_length))
    _exit(1);
  if (memchr(command, '\0', hello.command_length))
    _exit(1);
  command[hello.command_length] = '\0';

  char *environment = NULL;
  if (hello.environment_length) {
    environment = malloc((size_t)hello.environment_length);
    if (!environment || !read_all(cfd, environment, hello.environment_length))
      _exit(1);
    size_t offset = 0;
    while (offset < hello.environment_length) {
      size_t remaining = hello.environment_length - offset;
      size_t entry_length = strnlen(environment + offset, remaining);
      if (entry_length == remaining) {
        free(environment);
        free(command);
        _exit(1);
      }
      char *equals = memchr(environment + offset, '=', entry_length);
      if (!equals || equals == environment + offset) {
        free(environment);
        free(command);
        _exit(1);
      }
      for (char *key = environment + offset; key < equals; key++) {
        if (!( (*key >= 'A' && *key <= 'Z') || (*key >= 'a' && *key <= 'z') ||
               (*key >= '0' && *key <= '9') || *key == '_' )) {
          free(environment);
          free(command);
          _exit(1);
        }
      }
      offset += entry_length + 1;
    }
  }

  /* Create and open the PTY pair before switching mount namespaces. Android
   * can expose different /dev/ptmx and /dev/pts mounts in an app namespace;
   * keeping the already-open pair avoids attaching the child to a different
   * devpts instance after setns(). */
  int master = posix_openpt(O_RDWR | O_NOCTTY);
  if (master < 0 || grantpt(master) != 0 || unlockpt(master) != 0)
    _exit(1);
  char slave[128];
  if (ptsname_r(master, slave, sizeof(slave)) != 0) {
    _exit(1);
  }

  int slave_fd = open(slave, O_RDWR | O_NOCTTY);
  if (slave_fd < 0)
    _exit(1);
  struct termios term;
  if (tcgetattr(slave_fd, &term) == 0) {
    term.c_lflag &= (tcflag_t)~ECHO;
    (void)tcsetattr(slave_fd, TCSANOW, &term);
  }

  if (!(hello.flags & G4D_SU_FLAG_MOUNT_MASTER)) {
    char ns_path[64];
    snprintf(ns_path, sizeof(ns_path), "/proc/%d/ns/mnt", peer_pid);
    int nsfd = open(ns_path, O_RDONLY | O_CLOEXEC);
    if (peer_pid <= 0 || nsfd < 0 || setns(nsfd, CLONE_NEWNS) != 0) {
      int32_t result = G4D_SU_ERROR_MOUNT_NS;
      (void)send_frame(cfd, G4D_MSG_EXIT, &result, sizeof(result));
      if (nsfd >= 0)
        close(nsfd);
      close(slave_fd);
      close(master);
      free(environment);
      free(command);
      _exit(0);
    }
    close(nsfd);
    if (chdir("/") != 0) {
      int32_t result = G4D_SU_ERROR_MOUNT_NS;
      (void)send_frame(cfd, G4D_MSG_EXIT, &result, sizeof(result));
      close(slave_fd);
      close(master);
      free(environment);
      free(command);
      _exit(0);
    }
  }

  struct sigaction default_chld;
  memset(&default_chld, 0, sizeof(default_chld));
  default_chld.sa_handler = SIG_DFL;
  sigemptyset(&default_chld.sa_mask);
  sigaction(SIGCHLD, &default_chld, NULL);

  pid_t pid = fork();
  if (pid == 0) {
    setsid();
    if (ioctl(slave_fd, TIOCSCTTY, 0) != 0)
      _exit(127);
    dup2(slave_fd, STDIN_FILENO);
    dup2(slave_fd, STDOUT_FILENO);
    dup2(slave_fd, STDERR_FILENO);
    if (slave_fd > STDERR_FILENO)
      close(slave_fd);
    close(master);
    close(cfd);
    setenv("HOME", "/root", 1);
    setenv("USER", "root", 1);
    setenv("LOGNAME", "root", 1);
    setenv("SHELL", G4D_SHELL, 1);
    setenv("PATH", "/system/bin:/system/xbin:/vendor/bin:/vendor/xbin", 1);
    for (size_t offset = 0; environment && offset < hello.environment_length;) {
      char *entry = environment + offset;
      size_t entry_length = strlen(entry);
      char *equals = strchr(entry, '=');
      *equals = '\0';
      setenv(entry, equals + 1, 1);
      offset += entry_length + 1;
    }
    signal(SIGPIPE, SIG_DFL);
    char *const argv[] = { (char *)"sh", (char *)"-c", command, NULL };
    execv(G4D_SHELL, argv);
    _exit(127);
  }
  close(slave_fd);
  free(environment);
  free(command);
  if (pid < 0)
    _exit(1);

  int client_open = 1;
  int master_open = 1;
  int child_done = 0;
  int status = 0;
  time_t child_done_at = 0;
  unsigned char buf[G4D_MAX_PAYLOAD];
  while (master_open) {
    struct pollfd pf[2] = {
      { .fd = client_open ? cfd : -1, .events = POLLIN },
      { .fd = master, .events = POLLIN },
    };
    int pr = poll(pf, 2, 100);
    if (pr < 0 && errno != EINTR)
      break;
    if (!child_done) {
      pid_t waited = waitpid(pid, &status, WNOHANG);
      if (waited == pid) {
        child_done = 1;
        child_done_at = time(NULL);
      }
    }
    if (client_open && pr > 0 && (pf[0].revents & POLLIN)) {
      struct g4d_frame frame;
      if (!recv_frame(cfd, &frame, buf, sizeof(buf))) {
        send_eof_to_pty(master);
        client_open = 0;
      } else if (frame.type == G4D_MSG_STDIN) {
        if (frame.length && !write_all(master, buf, frame.length))
          client_open = 0;
      } else if (frame.type == G4D_MSG_EOF && frame.length == 0) {
        send_eof_to_pty(master);
        client_open = 0;
      } else if (frame.type != G4D_MSG_RESIZE) {
        break;
      }
    }
    if (client_open && pr > 0 &&
        (pf[0].revents & (POLLHUP | POLLERR | POLLNVAL))) {
      send_eof_to_pty(master);
      client_open = 0;
    }
    if (pr > 0 && (pf[1].revents & (POLLIN | POLLHUP | POLLERR))) {
      ssize_t n = read(master, buf, sizeof(buf));
      if (n > 0) {
        if (!send_frame(cfd, G4D_MSG_STDOUT, buf, (size_t)n))
          break;
      } else if (n < 0 && errno != EINTR && errno != EAGAIN) {
        master_open = 0;
      } else if (n == 0) {
        master_open = 0;
      }
    }
    if (child_done && time(NULL) - child_done_at >= 2)
      master_open = 0;
  }
  if (!child_done) {
    if (waitpid(pid, &status, 0) == pid)
      child_done = 1;
  }
  int result = 1;
  if (child_done && WIFEXITED(status))
    result = WEXITSTATUS(status);
  else if (child_done && WIFSIGNALED(status))
    result = 128 + WTERMSIG(status);
  (void)send_frame(cfd, G4D_MSG_EXIT, &result, sizeof(result));
  close(master);
  close(cfd);
  _exit(0);
}

static int make_listener(const char *name) {
  int lfd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (lfd < 0)
    return -1;
  struct sockaddr_un un;
  memset(&un, 0, sizeof(un));
  un.sun_family = AF_UNIX;
  strcpy(un.sun_path + 1, name);
  socklen_t alen = sizeof(sa_family_t) + 1 + strlen(name);
  if (bind(lfd, (struct sockaddr *)&un, alen) != 0 || listen(lfd, 8) != 0) {
    close(lfd);
    return -1;
  }
  return lfd;
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

  const char *su_only = getenv("G4D_SU_ONLY");
#ifdef G4D_SU_ONLY_DEFAULT
  su_only = "1";
#endif
  int listeners[2] = { -1, -1 };
  int listener_count = 0;
  if (!su_only || strcmp(su_only, "1") != 0) {
    listeners[listener_count] = make_listener(G4D_NAME);
    if (listeners[listener_count] < 0) {
      fprintf(stderr, "g4d: bind @%s: %s\n", G4D_NAME, strerror(errno));
      _exit(1);
    }
    listener_count++;
  }
  listeners[listener_count] = make_listener(G4D_SU_NAME);
  if (listeners[listener_count] < 0) {
    fprintf(stderr, "g4d: bind @%s: %s\n", G4D_SU_NAME, strerror(errno));
    _exit(1);
  }
  listener_count++;
  signal(SIGPIPE, SIG_IGN);

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = SIG_DFL;
  sa.sa_flags = SA_NOCLDWAIT;
  sigaction(SIGCHLD, &sa, NULL);

  for (;;) {
    struct pollfd pf[2];
    for (int i = 0; i < listener_count; i++)
      pf[i] = (struct pollfd){ .fd = listeners[i], .events = POLLIN };
    int ready = poll(pf, (nfds_t)listener_count, -1);
    if (ready < 0) {
      if (errno == EINTR)
        continue;
      _exit(1);
    }
    int index = -1;
    for (int i = 0; i < listener_count; i++) {
      if (pf[i].revents & POLLIN) {
        index = i;
        break;
      }
    }
    if (index < 0)
      continue;
    int cfd = accept(listeners[index], NULL, NULL);
    if (cfd < 0) {
      if (errno == EINTR)
        continue;
      _exit(1);
    }
    struct ucred peer;
    if (!peer_ok(cfd, &peer)) {
      int32_t denied = G4D_SU_ERROR_DENIED;
      (void)send_frame(cfd, G4D_MSG_EXIT, &denied, sizeof(denied));
      close(cfd);
      continue;
    }
    pid_t s = fork();
    if (s == 0) {
      for (int i = 0; i < listener_count; i++)
        close(listeners[i]);
      signal(SIGPIPE, SIG_IGN);
      unsigned char prefix[6];
      if (!read_all(cfd, prefix, sizeof(prefix)))
        _exit(1);
      uint32_t magic;
      uint16_t version;
      memcpy(&magic, prefix, sizeof(magic));
      memcpy(&version, prefix + sizeof(magic), sizeof(version));
      if (magic != G4D_PROTO_MAGIC)
        _exit(1);
      if (version == G4D_PROTO_VERSION)
        session(cfd, prefix);
      if (version == G4D_SU_VERSION)
        session_su(cfd, prefix, peer.pid);
      _exit(1);
    }
    close(cfd);
  }
}
