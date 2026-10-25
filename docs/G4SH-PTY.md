# g4sh terminal bridge

`g4sh` gives each connection a root `/system/bin/sh` on a PTY. The older
bridge copied raw bytes over the abstract socket but did not transfer the
client's terminal dimensions, resize events, or terminal environment. Full
screen programs could consequently render at the wrong size or use incomplete
terminal capabilities.

The updated bridge uses the versioned protocol in
`src/daemon/g4d_protocol.h`:

- `g4sh` sends the initial row/column size, `TERM`, and optional `TERMINFO`.
- `g4d` applies the size to the PTY before launching the shell and exports the
  terminal variables in that shell.
- Input and output use length-framed messages, so resize events can be sent
  between input chunks.
- On `SIGWINCH`, `g4sh` reads the local terminal size and sends an update;
  `g4d` applies it with `TIOCSWINSZ`, which notifies the foreground PTY process
  group.

Build and deploy `g4d` and `g4sh` as a matched pair. The wire protocol changed;
an old daemon and a new client are incompatible. This repository change does
not update either binary on the phone.

## Arrow-key note

The byte bridge forwards arrow-key bytes without translating them. `ESC O A`
through `ESC O D` are application-cursor arrow sequences emitted by many
terminal emulators when the application has enabled cursor-key mode. If a
program prints those bytes as text instead of consuming them, check the
terminal type and terminfo entry visible in the root shell, and confirm the
program has placed the PTY in its interactive mode. Passing `TERM` and
`TERMINFO` through g4sh addresses missing environment values; it does not
rewrite key sequences or guarantee every program's terminfo setup.

## Device check (2026-10-25)

The updated `g4d` and `g4sh` were built with Android NDK r30 and tested as a
matched pair on the existing one-boot root session. A test daemon used the
separate abstract socket `@ghostlockd_ptytest`, leaving the existing
`@ghostlockd` service untouched. It ran in a private mount namespace on boot
ID `7fa6687b-4cd5-46e0-9b5e-9613c54ae845`.

An interactive client reported `stty size` as `24 80`, `TERM=xterm-256color`,
and the requested Termux `TERMINFO` path. `nnn` first exited with `set HOME`
because the root shell does not define `HOME`; setting
`HOME=/data/data/com.termux/files/home` for the launcher command let it start.
While it was open, `ps` showed UID 0. Sending the application-cursor down
sequence `ESC O B` moved the selection to the next entry. Pressing `q` returned
to the root shell and the launcher cleaned both alias mounts.

This verifies the PTY and arrow-key path for this terminal and firmware. The
test daemon and client are staged at `/data/local/tmp/a/g4d-ptytest` and
`/data/local/tmp/a/g4sh-ptytest`; the root daemon remains volatile and stops on
reboot. `g4exec` and `defex-exec.sh` are staged beside them for the guarded
launcher documented in `DEFEX-SAFEPLACE.md`.
