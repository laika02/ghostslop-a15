/*
 * g4exec — run one executable through the tested DEFEX path alias.
 *
 * g4exec itself must be started as /system/bin/lmkd from a private mount
 * namespace. scripts/defex-exec.sh prepares that namespace and temporarily
 * bind mounts this binary at the alias. g4exec then makes propagation
 * recursively private, checks the mount state, bind mounts the requested
 * executable over the alias, and detaches both aliases as soon as execve has
 * loaded the requested image.
 *
 * This is a root-only, device-specific research helper, not a su manager.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define DEFEX_ALIAS "/system/bin/lmkd"
#define PROBE_SRC "/data/local/tmp/a/.g4exec-probe-src"
#define PROBE_DST "/data/local/tmp/a/.g4exec-probe-dst"

extern char **environ;

static volatile sig_atomic_t child_pid;
static volatile sig_atomic_t caught_signal;

static void on_signal(int signo) {
  caught_signal = signo;
  if (child_pid > 0)
    kill((pid_t)child_pid, signo);
}

static int same_file(const struct stat *a, const struct stat *b) {
  return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}

/* Return the number of mountinfo records whose mountpoint is path. */
static int mount_count(const char *path, const char *mountinfo) {
  FILE *fp = fopen(mountinfo, "r");
  if (!fp)
    return -1;
  char *line = NULL;
  size_t cap = 0;
  int count = 0;
  while (getline(&line, &cap, fp) >= 0) {
    char *save = NULL;
    char *field = strtok_r(line, " ", &save);
    for (int index = 1; field && index < 5; index++)
      field = strtok_r(NULL, " ", &save);
    if (field && strcmp(field, path) == 0)
      count++;
  }
  free(line);
  fclose(fp);
  return count;
}

/* Ensure MS_REC|MS_PRIVATE actually removed all propagation relationships. */
static int propagation_is_private(void) {
  FILE *fp = fopen("/proc/self/mountinfo", "r");
  if (!fp)
    return 0;
  char *line = NULL;
  size_t cap = 0;
  int ok = 1;
  while (getline(&line, &cap, fp) >= 0 && ok) {
    char *save = NULL;
    char *field = strtok_r(line, " ", &save);
    int index = 0;
    while (field && strcmp(field, "-") != 0) {
      index++;
      if (index >= 7 &&
          (!strncmp(field, "shared:", 7) ||
           !strncmp(field, "master:", 7) ||
           !strncmp(field, "propagate_from:", 15))) {
        ok = 0;
        break;
      }
      field = strtok_r(NULL, " ", &save);
    }
  }
  free(line);
  fclose(fp);
  return ok;
}

static int pid1_has_mount(const char *path) {
  int n = mount_count(path, "/proc/1/mountinfo");
  return n != 0;
}

static int prepare_private_namespace(void) {
  if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
    fprintf(stderr, "g4exec: recursive private mount failed: %s\n",
            strerror(errno));
    return 0;
  }
  if (!propagation_is_private()) {
    fprintf(stderr, "g4exec: mount propagation remains shared/slave\n");
    return 0;
  }
  return 1;
}

static int verify_new_mount_namespace(void) {
  const char *parent = getenv("G4DEFEX_PARENT_MNT");
  char current[128];
  if (!parent || !*parent) {
    fprintf(stderr, "g4exec: missing parent mount-namespace identity\n");
    return 0;
  }
  ssize_t n = readlink("/proc/self/ns/mnt", current, sizeof(current) - 1);
  if (n < 0) {
    fprintf(stderr, "g4exec: cannot read current mount namespace: %s\n",
            strerror(errno));
    return 0;
  }
  current[n] = '\0';
  if (strcmp(parent, current) == 0) {
    fprintf(stderr, "g4exec: unshare did not create a new mount namespace\n");
    return 0;
  }
  return 1;
}

static int self_test(void) {
  int src_fd = open(PROBE_SRC, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (src_fd < 0) {
    fprintf(stderr, "g4exec: probe source exists or cannot be created: %s\n",
            strerror(errno));
    return 1;
  }
  const char marker = 's';
  if (write(src_fd, &marker, 1) != 1 || close(src_fd) != 0) {
    fprintf(stderr, "g4exec: probe source write failed\n");
    unlink(PROBE_SRC);
    return 1;
  }

  int dst_fd = open(PROBE_DST, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (dst_fd < 0) {
    fprintf(stderr, "g4exec: probe target exists or cannot be created: %s\n",
            strerror(errno));
    unlink(PROBE_SRC);
    return 1;
  }
  const char marker2 = 'd';
  if (write(dst_fd, &marker2, 1) != 1 || close(dst_fd) != 0) {
    fprintf(stderr, "g4exec: probe target write failed\n");
    unlink(PROBE_SRC);
    unlink(PROBE_DST);
    return 1;
  }

  int ok = 0;
  if (mount(PROBE_SRC, PROBE_DST, NULL, MS_BIND, NULL) != 0) {
    fprintf(stderr, "g4exec: disposable bind mount failed: %s\n",
            strerror(errno));
    goto out;
  }
  if (mount_count(PROBE_DST, "/proc/self/mountinfo") != 1) {
    fprintf(stderr, "g4exec: disposable mount not found exactly once\n");
    goto cleanup_mount;
  }
  if (pid1_has_mount(PROBE_DST)) {
    fprintf(stderr, "g4exec: disposable mount appeared in PID 1 namespace\n");
    goto cleanup_mount;
  }
  if (umount2(PROBE_DST, MNT_DETACH) != 0) {
    fprintf(stderr, "g4exec: disposable mount cleanup failed: %s\n",
            strerror(errno));
    goto out;
  }
  if (mount_count(PROBE_DST, "/proc/self/mountinfo") != 0 ||
      pid1_has_mount(PROBE_DST)) {
    fprintf(stderr, "g4exec: disposable mount remained after cleanup\n");
    goto out;
  }
  ok = 1;
  goto out;

cleanup_mount:
  (void)umount2(PROBE_DST, MNT_DETACH);
out:
  unlink(PROBE_SRC);
  unlink(PROBE_DST);
  if (ok)
    fprintf(stderr, "g4exec: disposable private-namespace mount check passed\n");
  return ok ? 0 : 1;
}

static int bootstrap_is_ours(int *inherited_mounts) {
  struct stat executable, alias;
  if (stat("/proc/self/exe", &executable) != 0 ||
      stat(DEFEX_ALIAS, &alias) != 0 || !same_file(&executable, &alias)) {
    fprintf(stderr, "g4exec: expected helper is not mounted at %s\n",
            DEFEX_ALIAS);
    return 0;
  }
  int count = mount_count(DEFEX_ALIAS, "/proc/self/mountinfo");
  if (count < 1) {
    fprintf(stderr, "g4exec: helper alias mount is missing (%d mounts)\n",
            count);
    return 0;
  }
  *inherited_mounts = count - 1;
  return 1;
}

static int run_target(int argc, char **argv, int inherited_mounts) {
  const char *target = argv[1];
  struct stat target_stat, current_stat, alias_stat;
  if (stat(target, &target_stat) != 0 || !S_ISREG(target_stat.st_mode) ||
      access(target, X_OK) != 0) {
    fprintf(stderr, "g4exec: target is not an executable regular file: %s\n",
            target);
    return 1;
  }
  if (stat("/proc/self/exe", &current_stat) != 0 ||
      stat(DEFEX_ALIAS, &alias_stat) != 0 ||
      !same_file(&current_stat, &alias_stat)) {
    fprintf(stderr, "g4exec: helper alias changed before target mount\n");
    return 1;
  }
  if (pid1_has_mount(DEFEX_ALIAS)) {
    fprintf(stderr, "g4exec: alias unexpectedly visible in PID 1 namespace\n");
    return 1;
  }
  if (mount(target, DEFEX_ALIAS, NULL, MS_BIND, NULL) != 0) {
    fprintf(stderr, "g4exec: bind mount of target failed: %s\n",
            strerror(errno));
    return 1;
  }

  /* The bootstrap helper is already mounted once; this adds one layer. */
  int owned_mounts = 1;
  int rc = 1;
  owned_mounts++;
  if (mount_count(DEFEX_ALIAS, "/proc/self/mountinfo") !=
          inherited_mounts + 2 ||
      stat(DEFEX_ALIAS, &alias_stat) != 0 ||
      !same_file(&target_stat, &alias_stat) ||
      pid1_has_mount(DEFEX_ALIAS)) {
    fprintf(stderr, "g4exec: target overlay verification failed\n");
    goto cleanup;
  }

  char **child_argv = calloc((size_t)argc, sizeof(*child_argv));
  if (!child_argv) {
    fprintf(stderr, "g4exec: argv allocation failed\n");
    goto cleanup;
  }
  const char *base = strrchr(target, '/');
  child_argv[0] = (char *)(base ? base + 1 : target);
  for (int i = 2; i < argc; i++)
    child_argv[i - 1] = argv[i];

  int exec_pipe[2];
  if (pipe2(exec_pipe, O_CLOEXEC) != 0) {
    fprintf(stderr, "g4exec: exec status pipe failed: %s\n", strerror(errno));
    free(child_argv);
    goto cleanup;
  }

  struct sigaction sa, old_int, old_term, old_hup, old_quit;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = on_signal;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGINT, &sa, &old_int);
  sigaction(SIGTERM, &sa, &old_term);
  sigaction(SIGHUP, &sa, &old_hup);
  sigaction(SIGQUIT, &sa, &old_quit);

  pid_t child = fork();
  if (child == 0) {
    close(exec_pipe[0]);
    execve(DEFEX_ALIAS, child_argv, environ);
    int exec_errno = errno;
    (void)write(exec_pipe[1], &exec_errno, sizeof(exec_errno));
    dprintf(STDERR_FILENO, "g4exec: execve(%s): %s\n", DEFEX_ALIAS,
            strerror(exec_errno));
    _exit(127);
  }
  close(exec_pipe[1]);
  if (child < 0) {
    fprintf(stderr, "g4exec: fork failed: %s\n", strerror(errno));
  } else {
    child_pid = child;
    int exec_errno = 0;
    unsigned char *err_bytes = (unsigned char *)&exec_errno;
    size_t err_used = 0;
    int exec_ok = 0;
    for (;;) {
      ssize_t n = read(exec_pipe[0], err_bytes + err_used,
                       sizeof(exec_errno) - err_used);
      if (n < 0 && errno == EINTR)
        continue;
      if (n < 0) {
        fprintf(stderr, "g4exec: exec status read failed: %s\n",
                strerror(errno));
        break;
      }
      if (n == 0) {
        exec_ok = err_used == 0;
        break;
      }
      err_used += (size_t)n;
      if (err_used == sizeof(exec_errno))
        break;
    }
    close(exec_pipe[0]);

    if (exec_ok) {
      /* The target image is loaded. Detach both temporary aliases now so a
       * long-running shell can launch further commands through g4run. */
      while (owned_mounts > 0) {
        int count = mount_count(DEFEX_ALIAS, "/proc/self/mountinfo");
        if (count != inherited_mounts + owned_mounts ||
            umount2(DEFEX_ALIAS, MNT_DETACH) != 0) {
          fprintf(stderr,
                  "g4exec: could not detach aliases after exec "
                  "(inherited=%d owned=%d visible=%d): %s\n",
                  inherited_mounts, owned_mounts, count, strerror(errno));
          rc = 1;
          (void)kill(child, SIGKILL);
          break;
        }
        owned_mounts--;
        if (mount_count(DEFEX_ALIAS, "/proc/self/mountinfo") !=
            inherited_mounts + owned_mounts) {
          fprintf(stderr, "g4exec: alias count changed during cleanup\n");
          rc = 1;
          (void)kill(child, SIGKILL);
          break;
        }
      }
    } else if (err_used == sizeof(exec_errno)) {
      fprintf(stderr, "g4exec: target exec failed: %s\n",
              strerror(exec_errno));
    } else {
      if (!caught_signal)
        fprintf(stderr, "g4exec: target exec status was inconclusive\n");
      (void)kill(child, SIGKILL);
    }

    int status = 0;
    pid_t waited;
    do {
      waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    child_pid = 0;
    if (waited < 0) {
      fprintf(stderr, "g4exec: waitpid failed: %s\n", strerror(errno));
    } else if (WIFEXITED(status)) {
      rc = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
      rc = 128 + WTERMSIG(status);
    }
  }

  sigaction(SIGINT, &old_int, NULL);
  sigaction(SIGTERM, &old_term, NULL);
  sigaction(SIGHUP, &old_hup, NULL);
  sigaction(SIGQUIT, &old_quit, NULL);
  free(child_argv);

cleanup:
  while (owned_mounts > 0) {
    int count = mount_count(DEFEX_ALIAS, "/proc/self/mountinfo");
    if (count != inherited_mounts + owned_mounts) {
      fprintf(stderr,
              "g4exec: alias mount count changed unexpectedly "
              "(inherited=%d owned=%d visible=%d)\n",
              inherited_mounts, owned_mounts, count);
      rc = 1;
      break;
    }
    if (umount2(DEFEX_ALIAS, MNT_DETACH) != 0) {
      fprintf(stderr, "g4exec: alias cleanup failed: %s\n", strerror(errno));
      rc = 1;
      break;
    }
    owned_mounts--;
  }
  if (mount_count(DEFEX_ALIAS, "/proc/self/mountinfo") != inherited_mounts ||
      pid1_has_mount(DEFEX_ALIAS)) {
    fprintf(stderr, "g4exec: alias cleanup verification failed\n");
    rc = 1;
  }
  if (caught_signal)
    rc = 128 + caught_signal;
  return rc;
}

int main(int argc, char **argv) {
  if (!verify_new_mount_namespace())
    return 1;
  unsetenv("G4DEFEX_PARENT_MNT");
  unsetenv("G4DEFEX_PRIVATE_NS");
  if (!prepare_private_namespace())
    return 1;
  int inherited_mounts = 0;
  if (!bootstrap_is_ours(&inherited_mounts))
    return 1;
  if (pid1_has_mount(DEFEX_ALIAS)) {
    fprintf(stderr, "g4exec: refusing to proceed while PID 1 has alias mount\n");
    return 1;
  }
  if (argc == 2 && strcmp(argv[1], "--self-test") == 0)
    return self_test();
  if (argc < 2) {
    fprintf(stderr, "usage: g4exec EXECUTABLE [ARG ...]\n");
    return 2;
  }
  return run_target(argc, argv, inherited_mounts);
}
