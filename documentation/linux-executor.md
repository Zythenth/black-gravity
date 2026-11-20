# Linux Bubblewrap test executor

Technical reference for the `linux-bwrap` executor used by `black_gravity_test`. Installation, the commands that need root and the AppArmor case are in the [README](../README.md#linux-bubblewrap-test-executor-linux-bwrap).

## Selection and refusals

Setting `BRIDGE_TEST_EXECUTOR=linux-bwrap` requires Bubblewrap: if unavailable, `black_gravity_test` refuses before queuing with `LINUX_BWRAP_MISSING` or `LINUX_USER_NAMESPACES_BLOCKED` and never falls back to host execution.

`black_gravity_health.testExecutor` reports `selected`, `explicit`, and `linuxBwrap` availability details (`available`, `path`, `version`, `code`, `reason`).

## Mounts, writable paths and seccomp

The sandbox root itself is read-only and exposes only system directories (`/usr`, `/bin`, `/sbin`, `/lib*`, `/etc`, `/opt`, `/nix/store`, read-only, with system roots that are symbolic links on the host recreated as symbolic links inside the sandbox), the Node and `PATH` toolchain directories (read-only, mounted after the `/tmp` and `/run` `tmpfs`, including directories reached through symlinks at their original path, never the home directory; toolchains that are `/tmp`, `/run`, or `XDG_RUNTIME_DIR` themselves, or contain them, are refused), the copy, a scratch directory, and the declared `readPaths`/`writePaths`; only the copy, the scratch directory, `/tmp`, and declared `writePaths` are writable; the home directory and `/var` are not visible; `/tmp` is an empty per-run `tmpfs`; `/run`, `XDG_RUNTIME_DIR`, and protected paths are empty read-only `tmpfs` mounts; when network is disabled (the default), a seccomp filter blocks creating `AF_UNIX` sockets and `io_uring`, and limits `socketpair` to stream and seqpacket types (other types, including datagram and raw, are blocked), while pipes still work, so host Unix sockets are unreachable; test commands that need Unix sockets require network enabled in the sandbox policy; the filter supports `x86_64` and `arm64`, and other architectures are refused when network is disabled.

## FIFOs and directories that cannot be listed

Execution is also refused when an automatically mounted directory (toolchains, their aliases, or `readPaths`) contains a FIFO, because read-only mounts do not stop writes to named pipes; the run is also refused when such a directory cannot be traversed or listed (a command inside the sandbox can regain access to the user's own directories through a nested user namespace); system roots are not scanned.

## Threat model

Threat model: system roots (`/usr`, `/etc`, `/opt`, and the other system directories listed above) are trusted and controlled by the administrator; FIFOs and other pre-existing channels inside them are outside the scope of this executor in this version.
