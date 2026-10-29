/*
 * g4mount — boot-only /system/bin/su overlay manager.
 *
 * Run as root through the DEFEX-safe /system/bin/lmkd alias. It installs a
 * tmpfs-backed overlay in each live zygote mount namespace so new app
 * processes inherit /system/bin/su without modifying a system partition.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define SU_SOURCE "/data/local/tmp/a/g4su"
#define RAM_DIR "/data/local/tmp/.ghostlock-su"
#define UPPER_DIR RAM_DIR "/upper"
#define WORK_DIR RAM_DIR "/work"
#define SYSTEM_BIN "/system/bin"
#define SU_PATH "/system/bin/su"
#define SAFE_ALIAS_PATH "/system/bin/lmkd"
#define SAFE_ALIAS_NAME "lmkd"
#define MAX_ZYGOTES 16

struct zygote_ns {
  pid_t pid;
  int nsfd;
  dev_t dev;
  ino_t ino;
  int installed;
};

static int read_mount_record(const char *path, char *fstype, size_t fstype_cap,
                             char *source, size_t source_cap, int *count) {
  FILE *fp = fopen("/proc/self/mountinfo", "r");
  if (!fp)
    return 0;
  char *line = NULL;
  size_t cap = 0;
  *count = 0;
  int found = 1;
  while (getline(&line, &cap, fp) >= 0) {
    char *save = NULL;
    char *fields[128];
    int n = 0;
    for (char *field = strtok_r(line, " ", &save); field && n < 128;
         field = strtok_r(NULL, " ", &save))
      fields[n++] = field;
    if (n < 10)
      continue;
    /* Field 5 is the mountpoint; the separator precedes fs type/source. */
    if (strcmp(fields[4], path) != 0)
      continue;
    int sep = -1;
    for (int i = 6; i < n; i++) {
      if (strcmp(fields[i], "-") == 0) {
        sep = i;
        break;
      }
    }
    if (sep < 0 || sep + 2 >= n) {
      found = 0;
      break;
    }
    if (*count == 0) {
      snprintf(fstype, fstype_cap, "%s", fields[sep + 1]);
      snprintf(source, source_cap, "%s", fields[sep + 2]);
    }
    (*count)++;
  }
  free(line);
  fclose(fp);
  return found;
}

static int mountpoint_covers(const char *mountpoint, const char *path) {
  if (strcmp(mountpoint, "/") == 0)
    return path[0] == '/';
  size_t length = strlen(mountpoint);
  return strncmp(mountpoint, path, length) == 0 &&
         (path[length] == '\0' || path[length] == '/');
}

/* A mount made beneath a shared mount propagates to its peers. The path being
 * mounted over is often not itself a mountpoint (notably /system/bin), so
 * find the closest mountpoint that contains it and make that subtree a slave.
 * Slave mounts still receive changes from their master but do not propagate
 * our temporary overlays back to init or sibling mount namespaces. */
static int isolate_mount_path(const char *path) {
  FILE *fp = fopen("/proc/self/mountinfo", "r");
  if (!fp) {
    fprintf(stderr, "g4mount: cannot read mountinfo: %s\n", strerror(errno));
    return 0;
  }
  char *line = NULL;
  size_t capacity = 0;
  char selected[512] = {0};
  size_t selected_length = 0;
  int selected_shared = 0;
  while (getline(&line, &capacity, fp) >= 0) {
    char *save = NULL;
    char *fields[128];
    int count = 0;
    for (char *field = strtok_r(line, " ", &save);
         field && count < 128; field = strtok_r(NULL, " ", &save))
      fields[count++] = field;
    if (count < 10)
      continue;
    int separator = -1;
    for (int i = 6; i < count; i++) {
      if (strcmp(fields[i], "-") == 0) {
        separator = i;
        break;
      }
    }
    if (separator < 0 || !mountpoint_covers(fields[4], path))
      continue;
    size_t length = strlen(fields[4]);
    if (length < selected_length || length >= sizeof(selected))
      continue;
    selected_length = length;
    memcpy(selected, fields[4], length + 1);
    selected_shared = 0;
    for (int i = 6; i < separator; i++) {
      if (strncmp(fields[i], "shared:", 7) == 0) {
        selected_shared = 1;
        break;
      }
    }
  }
  free(line);
  fclose(fp);
  if (selected_length == 0) {
    fprintf(stderr, "g4mount: no mountpoint contains %s\n", path);
    return 0;
  }
  if (!selected_shared)
    return 1;
  if (mount(NULL, selected, NULL, MS_REC | MS_SLAVE, NULL) != 0) {
    fprintf(stderr, "g4mount: cannot isolate propagation under %s: %s\n",
            selected, strerror(errno));
    return 0;
  }
  return 1;
}

static int source_is_zygote(pid_t pid) {
  char path[64];
  char cmdline[512];
  snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
  FILE *fp = fopen(path, "r");
  if (!fp)
    return 0;
  size_t length = fread(cmdline, 1, sizeof(cmdline) - 1, fp);
  fclose(fp);
  if (length == 0)
    return 0;
  cmdline[length] = '\0';

  /* Android commonly sets comm to "main" for ART zygotes. The process
   * command line retains the zygote name, so inspect argv instead. */
  const char *arg0 = cmdline;
  const char *arg0_end = memchr(arg0, '\0', length);
  if (!arg0_end)
    arg0_end = cmdline + length;
  const char *base = strrchr(arg0, '/');
  base = base ? base + 1 : arg0;
  size_t base_length = (size_t)(arg0_end - base);
  if ((base_length == 6 && memcmp(base, "zygote", 6) == 0) ||
      (base_length == 8 && memcmp(base, "zygote64", 8) == 0) ||
      (base_length == 8 && memcmp(base, "zygote32", 8) == 0) ||
      (base_length == 14 && memcmp(base, "webview_zygote", 14) == 0))
    return 1;

  /* Also accept app_process-style argv used by some Android builds, but only
   * when the executable is app_process and it explicitly has --zygote. */
  if (strcmp(base, "app_process") != 0 &&
      strcmp(base, "app_process32") != 0 &&
      strcmp(base, "app_process64") != 0)
    return 0;
  const char *limit = cmdline + length;
  if (arg0_end == limit)
    return 0;
  for (const char *arg = arg0_end + 1; arg < limit;) {
    size_t remaining = (size_t)(limit - arg);
    const char *arg_end = memchr(arg, '\0', remaining);
    if (!arg_end)
      arg_end = limit;
    if ((size_t)(arg_end - arg) == 8 && memcmp(arg, "--zygote", 8) == 0)
      return 1;
    if (arg_end == limit)
      break;
    arg = arg_end + 1;
  }
  return 0;
}

static int collect_zygotes(struct zygote_ns *items, size_t *count) {
  DIR *proc = opendir("/proc");
  if (!proc)
    return 0;
  *count = 0;
  struct dirent *entry;
  while ((entry = readdir(proc)) != NULL) {
    char *end = NULL;
    long raw = strtol(entry->d_name, &end, 10);
    if (!entry->d_name[0] || !end || *end || raw <= 1 || raw > INT32_MAX ||
        !source_is_zygote((pid_t)raw))
      continue;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%ld/ns/mnt", raw);
    int nsfd = open(path, O_RDONLY | O_CLOEXEC);
    if (nsfd < 0)
      continue;
    struct stat st;
    if (fstat(nsfd, &st) != 0) {
      close(nsfd);
      continue;
    }
    int duplicate = 0;
    for (size_t i = 0; i < *count; i++) {
      if (items[i].dev == st.st_dev && items[i].ino == st.st_ino) {
        duplicate = 1;
        break;
      }
    }
    if (duplicate) {
      close(nsfd);
      continue;
    }
    if (*count == MAX_ZYGOTES) {
      close(nsfd);
      break;
    }
    items[*count] = (struct zygote_ns){
      .pid = (pid_t)raw,
      .nsfd = nsfd,
      .dev = st.st_dev,
      .ino = st.st_ino,
      .installed = 0,
    };
    (*count)++;
  }
  closedir(proc);
  return *count > 0;
}

static int ensure_empty_dir(void) {
  if (mkdir(RAM_DIR, 0700) != 0 && errno != EEXIST) {
    fprintf(stderr, "g4mount: cannot create RAM mountpoint: %s\n",
            strerror(errno));
    return 0;
  }
  struct stat st;
  if (lstat(RAM_DIR, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != 0) {
    fprintf(stderr, "g4mount: RAM mountpoint is not a root-owned directory\n");
    return 0;
  }
  DIR *dir = opendir(RAM_DIR);
  if (!dir)
    return 0;
  int empty = 1;
  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL) {
    if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) {
      empty = 0;
      break;
    }
  }
  closedir(dir);
  if (!empty) {
    fprintf(stderr, "g4mount: refusing a non-empty RAM mountpoint\n");
    return 0;
  }
  return chmod(RAM_DIR, 0700) == 0;
}

/* OverlayFS reports the metadata of the upper directory for the merged
 * mountpoint. Match /system/bin so the overlay keeps the same traversal
 * permissions and ownership as the lower directory. */
static int create_overlay_dirs(void) {
  struct stat system_bin;
  if (stat(SYSTEM_BIN, &system_bin) != 0 || !S_ISDIR(system_bin.st_mode) ||
      system_bin.st_uid != 0) {
    fprintf(stderr, "g4mount: cannot read root-owned %s metadata: %s\n",
            SYSTEM_BIN, strerror(errno));
    return 0;
  }
  mode_t bin_mode = system_bin.st_mode & 07777;
  if (mkdir(UPPER_DIR, bin_mode) != 0 ||
      chown(UPPER_DIR, system_bin.st_uid, system_bin.st_gid) != 0 ||
      chmod(UPPER_DIR, bin_mode) != 0 || mkdir(WORK_DIR, 0700) != 0) {
    fprintf(stderr, "g4mount: cannot create overlay work directories: %s\n",
            strerror(errno));
    return 0;
  }
  return 1;
}

static void cleanup_ram_dir(void) {
  (void)unlink(UPPER_DIR "/su");
  (void)unlink(UPPER_DIR "/" SAFE_ALIAS_NAME);
  (void)rmdir(UPPER_DIR);
  (void)rmdir(WORK_DIR);
  (void)rmdir(RAM_DIR);
}

static int trusted_alias_is_regular(void) {
  struct stat st;
  if (lstat(SAFE_ALIAS_PATH, &st) != 0 || !S_ISREG(st.st_mode) ||
      st.st_uid != 0 || (st.st_mode & 0111) == 0) {
    fprintf(stderr,
            "g4mount: refusing non-regular or non-executable alias path %s\n",
            SAFE_ALIAS_PATH);
    return 0;
  }
  return 1;
}

static int copy_client_to_upper(void) {
  char destination[512];
  snprintf(destination, sizeof(destination), "%s/%s", UPPER_DIR,
           SAFE_ALIAS_NAME);
  int source_fd = open(SU_SOURCE, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (source_fd < 0) {
    fprintf(stderr, "g4mount: cannot open staged su client: %s\n",
            strerror(errno));
    return 0;
  }
  struct stat source_stat;
  if (fstat(source_fd, &source_stat) != 0 || !S_ISREG(source_stat.st_mode) ||
      source_stat.st_size <= 0 || source_stat.st_size > 16 * 1024 * 1024) {
    fprintf(stderr, "g4mount: staged su client has an invalid size or type\n");
    close(source_fd);
    return 0;
  }
  int destination_fd = open(destination,
                            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                            0700);
  if (destination_fd < 0) {
    fprintf(stderr, "g4mount: cannot create system-labeled su copy: %s\n",
            strerror(errno));
    close(source_fd);
    return 0;
  }

  char buffer[65536];
  int ok = 1;
  for (;;) {
    ssize_t count = read(source_fd, buffer, sizeof(buffer));
    if (count < 0 && errno == EINTR)
      continue;
    if (count < 0) {
      fprintf(stderr, "g4mount: read of staged su client failed: %s\n",
              strerror(errno));
      ok = 0;
      break;
    }
    if (count == 0)
      break;
    ssize_t offset = 0;
    while (offset < count) {
      ssize_t written = write(destination_fd, buffer + offset,
                              (size_t)(count - offset));
      if (written < 0 && errno == EINTR)
        continue;
      if (written <= 0) {
        fprintf(stderr, "g4mount: write of system-labeled su copy failed: %s\n",
                strerror(errno));
        ok = 0;
        break;
      }
      offset += written;
    }
    if (!ok)
      break;
  }
  if (ok && (fchown(destination_fd, 0, 0) != 0 ||
             fchmod(destination_fd, 0755) != 0)) {
    fprintf(stderr, "g4mount: cannot set copied su ownership or mode: %s\n",
            strerror(errno));
    ok = 0;
  }
  if (close(source_fd) != 0)
    ok = 0;
  if (close(destination_fd) != 0)
    ok = 0;
  if (!ok)
    unlink(destination);
  return ok;
}

static int upper_su_is_alias(void) {
  char target[64];
  ssize_t n = readlink(UPPER_DIR "/su", target, sizeof(target) - 1);
  if (n < 0 || (size_t)n >= sizeof(target) - 1)
    return 0;
  target[n] = '\0';
  if (strcmp(target, SAFE_ALIAS_NAME) != 0)
    return 0;
  struct stat su;
  if (lstat(UPPER_DIR "/su", &su) != 0 || !S_ISLNK(su.st_mode) ||
      su.st_uid != 0)
    return 0;
  return 1;
}

static int files_have_same_contents(const char *first, const char *second) {
  int first_fd = open(first, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  int second_fd = open(second, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (first_fd < 0 || second_fd < 0) {
    if (first_fd >= 0)
      close(first_fd);
    if (second_fd >= 0)
      close(second_fd);
    return 0;
  }
  struct stat first_stat, second_stat;
  if (fstat(first_fd, &first_stat) != 0 || fstat(second_fd, &second_stat) != 0 ||
      !S_ISREG(first_stat.st_mode) || !S_ISREG(second_stat.st_mode) ||
      first_stat.st_size != second_stat.st_size) {
    close(first_fd);
    close(second_fd);
    return 0;
  }
  char first_buffer[65536], second_buffer[65536];
  int same = 1;
  for (;;) {
    ssize_t first_count;
    do {
      first_count = read(first_fd, first_buffer, sizeof(first_buffer));
    } while (first_count < 0 && errno == EINTR);
    ssize_t second_count;
    do {
      second_count = read(second_fd, second_buffer, sizeof(second_buffer));
    } while (second_count < 0 && errno == EINTR);
    if (first_count < 0 || second_count < 0 || first_count != second_count ||
        (first_count > 0 &&
         memcmp(first_buffer, second_buffer, (size_t)first_count) != 0)) {
      same = 0;
      break;
    }
    if (first_count == 0)
      break;
  }
  close(first_fd);
  close(second_fd);
  return same;
}

static int alias_mount_is_client(void) {
  char fs[64] = {0}, source[128] = {0};
  int count = 0;
  if (!read_mount_record(SAFE_ALIAS_PATH, fs, sizeof(fs), source,
                         sizeof(source), &count) || count != 1)
    return 0;
  struct stat alias, client;
  return stat(SAFE_ALIAS_PATH, &alias) == 0 && stat(SU_SOURCE, &client) == 0 &&
         S_ISREG(alias.st_mode) && S_ISREG(client.st_mode) &&
         alias.st_dev == client.st_dev && alias.st_ino == client.st_ino &&
         alias.st_uid == 0 && (alias.st_mode & 0111) != 0;
}

static int alias_copy_is_client(void) {
  char fs[64] = {0}, source[128] = {0};
  int count = 0;
  if (!read_mount_record(SAFE_ALIAS_PATH, fs, sizeof(fs), source,
                         sizeof(source), &count) || count != 0)
    return 0;
  struct stat alias, client;
  return stat(SAFE_ALIAS_PATH, &alias) == 0 && stat(SU_SOURCE, &client) == 0 &&
         S_ISREG(alias.st_mode) && S_ISREG(client.st_mode) &&
         alias.st_uid == 0 && client.st_uid == 0 &&
         (alias.st_mode & 0111) != 0 && alias.st_size == client.st_size &&
         files_have_same_contents(SAFE_ALIAS_PATH, SU_SOURCE);
}

static int su_path_is_alias_symlink(void) {
  char target[64];
  ssize_t n = readlink(SU_PATH, target, sizeof(target) - 1);
  if (n < 0 || (size_t)n >= sizeof(target) - 1)
    return 0;
  target[n] = '\0';
  struct stat link;
  if (strcmp(target, SAFE_ALIAS_NAME) != 0 ||
      lstat(SU_PATH, &link) != 0 || !S_ISLNK(link.st_mode) ||
      link.st_uid != 0)
    return 0;
  return 1;
}

static int mounted_su_is_copy_alias(void) {
  if (!su_path_is_alias_symlink() || !alias_copy_is_client() ||
      access(SU_PATH, X_OK) != 0)
    return 0;
  struct stat su, alias;
  return stat(SU_PATH, &su) == 0 && stat(SAFE_ALIAS_PATH, &alias) == 0 &&
         S_ISREG(su.st_mode) && S_ISREG(alias.st_mode) &&
         su.st_uid == 0 && (su.st_mode & 0111) != 0;
}

static int mounted_su_is_bind_alias(void) {
  if (!su_path_is_alias_symlink() || !alias_mount_is_client() ||
      access(SU_PATH, X_OK) != 0)
    return 0;
  struct stat su, alias;
  return stat(SU_PATH, &su) == 0 && stat(SAFE_ALIAS_PATH, &alias) == 0 &&
         S_ISREG(su.st_mode) && S_ISREG(alias.st_mode) &&
         su.st_dev == alias.st_dev && su.st_ino == alias.st_ino &&
         su.st_uid == 0 && (su.st_mode & 0111) != 0;
}

static int mounted_su_is_alias(void) {
  return mounted_su_is_copy_alias() || mounted_su_is_bind_alias();
}

static int recognized_upper_layout(void) {
  struct stat su;
  if (lstat(UPPER_DIR "/su", &su) != 0 || su.st_uid != 0)
    return 0;
  if (S_ISREG(su.st_mode))
    return 1; /* Previous direct-path layout, retained for safe removal. */
  if (!S_ISLNK(su.st_mode) || !upper_su_is_alias())
    return 0;
  struct stat copied_alias;
  return (lstat(UPPER_DIR "/" SAFE_ALIAS_NAME, &copied_alias) == 0 &&
          S_ISREG(copied_alias.st_mode) && copied_alias.st_uid == 0) ||
         errno == ENOENT;
}

static int install_current(void) {
  char fs[64] = {0}, source[128] = {0};
  int count = 0;
  if (!read_mount_record(SYSTEM_BIN, fs, sizeof(fs), source, sizeof(source),
                         &count))
    return 0;
  if (count > 0) {
    if (count == 1 && strcmp(fs, "overlay") == 0 &&
        strcmp(source, "ghostlock-su") == 0 && mounted_su_is_alias()) {
      puts("Already installed with the /system/bin/lmkd alias.");
      return 2;
    }
    if (count == 1 && strcmp(fs, "overlay") == 0 &&
        strcmp(source, "ghostlock-su") == 0 && access(SU_PATH, X_OK) == 0) {
      fprintf(stderr,
              "g4mount: a legacy direct-path su overlay is active; remove it before reinstalling alias mode\n");
      return 0;
    }
    fprintf(stderr, "g4mount: refusing an unexpected mount on %s\n", SYSTEM_BIN);
    return 0;
  }
  memset(fs, 0, sizeof(fs));
  memset(source, 0, sizeof(source));
  int alias_mounts = 0;
  if (!read_mount_record(SAFE_ALIAS_PATH, fs, sizeof(fs), source,
                         sizeof(source), &alias_mounts) || alias_mounts != 0) {
    fprintf(stderr, "g4mount: refusing a pre-existing mount on %s\n",
            SAFE_ALIAS_PATH);
    return 0;
  }
  memset(fs, 0, sizeof(fs));
  memset(source, 0, sizeof(source));
  int ram_mounts = 0;
  if (!read_mount_record(RAM_DIR, fs, sizeof(fs), source, sizeof(source),
                         &ram_mounts) || ram_mounts != 0) {
    fprintf(stderr, "g4mount: refusing a pre-existing RAM mountpoint state\n");
    return 0;
  }
  struct stat existing;
  if (lstat(SU_PATH, &existing) == 0 || errno != ENOENT) {
    fprintf(stderr, "g4mount: refusing existing %s\n", SU_PATH);
    return 0;
  }
  if (!trusted_alias_is_regular())
    return 0;
  if (!ensure_empty_dir())
    return 0;
  if (!isolate_mount_path(SU_PATH) || !isolate_mount_path(RAM_DIR))
    return 0;
  /* g4su is launched by ordinary app processes. Give the RAM-backed copy
   * Android's generic system_file label, which app domains can execute. The
   * lmkd_exec label is for lmkd's own entrypoint and is not the app-facing
   * su client's label. DEFEX's root-process SafePlace rule is separate. */
  if (mount("tmpfs", RAM_DIR, "tmpfs", MS_NOSUID | MS_NODEV,
            "size=16m,mode=0700,context=u:object_r:system_file:s0") != 0) {
    fprintf(stderr, "g4mount: tmpfs mount failed: %s\n", strerror(errno));
    return 0;
  }
  if (!create_overlay_dirs()) {
    umount2(RAM_DIR, MNT_DETACH);
    cleanup_ram_dir();
    return 0;
  }
  if (symlink(SAFE_ALIAS_NAME, UPPER_DIR "/su") != 0) {
    fprintf(stderr, "g4mount: cannot create su alias symlink: %s\n",
            strerror(errno));
    umount2(RAM_DIR, MNT_DETACH);
    cleanup_ram_dir();
    return 0;
  }
  if (!copy_client_to_upper()) {
    umount2(RAM_DIR, MNT_DETACH);
    cleanup_ram_dir();
    return 0;
  }

  char options[512];
  snprintf(options, sizeof(options), "lowerdir=/system/bin,upperdir=%s,workdir=%s",
           UPPER_DIR, WORK_DIR);
  if (mount("ghostlock-su", SYSTEM_BIN, "overlay",
            MS_NOSUID | MS_NODEV, options) != 0) {
    fprintf(stderr, "g4mount: overlay mount failed: %s\n", strerror(errno));
    umount2(RAM_DIR, MNT_DETACH);
    cleanup_ram_dir();
    return 0;
  }
  if (!mounted_su_is_alias()) {
    fprintf(stderr,
            "g4mount: labeled su copy or alias failed verification\n");
    umount2(SYSTEM_BIN, MNT_DETACH);
    umount2(RAM_DIR, MNT_DETACH);
    cleanup_ram_dir();
    return 0;
  }
  puts("Installed /system/bin/su as a symlink to a RAM-backed, system_file-labeled "
       "g4su copy at /system/bin/lmkd in this zygote namespace.");
  return 1;
}

static int remove_current(void) {
  char fs[64] = {0}, source[128] = {0};
  int count = 0;
  if (!read_mount_record(SYSTEM_BIN, fs, sizeof(fs), source, sizeof(source),
                         &count))
    return 0;
  int overlay_present = count != 0;
  if (overlay_present &&
      (count != 1 || strcmp(fs, "overlay") != 0 ||
       strcmp(source, "ghostlock-su") != 0)) {
    fprintf(stderr, "g4mount: refusing to unmount an unexpected mount\n");
    return 0;
  }
  char alias_fs[64] = {0}, alias_source[128] = {0};
  int alias_mounts = 0;
  if (!read_mount_record(SAFE_ALIAS_PATH, alias_fs, sizeof(alias_fs),
                         alias_source, sizeof(alias_source), &alias_mounts))
    return 0;
  if (alias_mounts != 0 &&
      (!overlay_present || alias_mounts != 1 || !mounted_su_is_bind_alias())) {
    fprintf(stderr, "g4mount: refusing an unexpected mount on %s\n",
            SAFE_ALIAS_PATH);
    return 0;
  }
  if (alias_mounts == 1 &&
      umount2(SAFE_ALIAS_PATH, MNT_DETACH) != 0) {
    fprintf(stderr, "g4mount: alias detach failed: %s\n", strerror(errno));
    return 0;
  }
  if (count == 0) {
    puts("No su overlay is installed in this zygote mount namespace.");
  } else {
    if (umount2(SYSTEM_BIN, MNT_DETACH) != 0) {
      fprintf(stderr, "g4mount: overlay detach failed: %s\n", strerror(errno));
      return 0;
    }
    puts("Removed the /system/bin/su alias overlay from this zygote namespace.");
  }
  memset(fs, 0, sizeof(fs));
  memset(source, 0, sizeof(source));
  count = 0;
  if (!read_mount_record(RAM_DIR, fs, sizeof(fs), source, sizeof(source),
                         &count))
    return 0;
  if (count == 1 && strcmp(fs, "tmpfs") == 0) {
    if (!recognized_upper_layout()) {
      fprintf(stderr, "g4mount: refusing an unrecognized tmpfs at RAM mountpoint\n");
      return 0;
    }
    if (umount2(RAM_DIR, MNT_DETACH) != 0) {
      fprintf(stderr, "g4mount: RAM overlay detach failed: %s\n",
              strerror(errno));
      return 0;
    }
    cleanup_ram_dir();
  } else if (count != 0) {
    fprintf(stderr, "g4mount: refusing unexpected RAM mount\n");
    return 0;
  }
  return 1;
}

static int switch_to_ns(int nsfd, int self_fd) {
  if (setns(nsfd, CLONE_NEWNS) == 0)
    return 1;
  fprintf(stderr, "g4mount: setns failed: %s\n", strerror(errno));
  (void)setns(self_fd, CLONE_NEWNS);
  return 0;
}

static void close_zygotes(struct zygote_ns *items, size_t count) {
  for (size_t i = 0; i < count; i++)
    if (items[i].nsfd >= 0)
      close(items[i].nsfd);
}

static int operate_zygotes(const char *operation) {
  struct zygote_ns items[MAX_ZYGOTES];
  memset(items, 0, sizeof(items));
  size_t count = 0;
  if (!collect_zygotes(items, &count)) {
    fprintf(stderr, "g4mount: no live zygote mount namespace found\n");
    return 1;
  }
  int self_fd = open("/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
  if (self_fd < 0) {
    close_zygotes(items, count);
    return 1;
  }
  int result = 0;
  for (size_t i = 0; i < count; i++) {
    printf("zygote PID %d: ", items[i].pid);
    fflush(stdout);
    if (!switch_to_ns(items[i].nsfd, self_fd)) {
      result = 1;
      break;
    }
    int ok;
    int newly_installed = 0;
    if (strcmp(operation, "install") == 0) {
      int state = install_current();
      ok = state > 0;
      newly_installed = state == 1;
    } else if (strcmp(operation, "remove") == 0)
      ok = remove_current();
    else {
      char fs[64] = {0}, source[128] = {0};
      int mounts = 0;
      ok = read_mount_record(SYSTEM_BIN, fs, sizeof(fs), source, sizeof(source),
                             &mounts);
      if (ok && mounts == 1 && strcmp(fs, "overlay") == 0 &&
          strcmp(source, "ghostlock-su") == 0 && mounted_su_is_alias())
        puts("su overlay installed with a RAM-backed, system_file-labeled "
             "/system/bin/lmkd alias.");
      else if (ok && mounts == 1 && strcmp(fs, "overlay") == 0 &&
               strcmp(source, "ghostlock-su") == 0 && access(SU_PATH, X_OK) == 0)
        puts("legacy direct-path su overlay installed; remove and reinstall for alias mode.");
      else if (ok && mounts == 0)
        puts("no su overlay.");
      else {
        fprintf(stderr, "unexpected su mount state.\n");
        ok = 0;
      }
    }
    if (setns(self_fd, CLONE_NEWNS) != 0) {
      fprintf(stderr, "g4mount: failed to restore caller namespace: %s\n",
              strerror(errno));
      result = 1;
      break;
    }
    if (!ok) {
      result = 1;
      break;
    }
    items[i].installed = newly_installed;
  }
  if (result != 0 && strcmp(operation, "install") == 0) {
    for (size_t i = 0; i < count; i++) {
      if (!items[i].installed)
        continue;
      if (switch_to_ns(items[i].nsfd, self_fd)) {
        (void)remove_current();
        (void)setns(self_fd, CLONE_NEWNS);
      }
    }
  }
  close(self_fd);
  close_zygotes(items, count);
  return result;
}

int main(int argc, char **argv) {
  if (geteuid() != 0) {
    fprintf(stderr, "g4mount: run this helper as root\n");
    return 1;
  }
  if (argc != 2 || (strcmp(argv[1], "install") != 0 &&
                    strcmp(argv[1], "remove") != 0 &&
                    strcmp(argv[1], "status") != 0)) {
    fprintf(stderr, "Usage: g4mount install|remove|status\n");
    return 2;
  }
  if (strcmp(argv[1], "install") == 0) {
    struct stat st;
    if (lstat(SU_SOURCE, &st) != 0 || !S_ISREG(st.st_mode) ||
        (st.st_mode & 0111) == 0) {
      fprintf(stderr, "g4mount: staged su client missing or not executable\n");
      return 1;
    }
  }
  return operate_zygotes(argv[1]);
}
