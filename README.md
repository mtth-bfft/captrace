# captrace

Lists capabilities used by processes at runtime, as they are requested, to assist in the task of creating custom hardened profiles for containers and sandboxes.
Tracing using [kprobes](https://www.kernel.org/doc/Documentation/kprobes.txt) heavily inspired by [capable](https://github.com/iovisor/bcc/blob/master/tools/capable.py).

## Usage

By default, all processes are displayed. Non-audited capability checks are discarded, but can be displayed using `-v`.

    sudo ./captrace
    669161.938696   1244   /usr/libexec/Xorg   CAP_IPC_OWNER
    669165.918900   1244   /usr/libexec/Xorg   CAP_IPC_OWNER
    669166.394339   1003   /usr/sbin/dmeventd  CAP_SYS_ADMIN
    [...]

To list capabilities of a specific process, use `-p <pid>`. Add `-f` to also list capabilities used by new child processes. To list capabilities used by a command from its very start, use `captrace` followed by that command:

    sudo ./captrace ping 127.0.0.1
    675412.284225    4629    /usr/bin/ping    CAP_SETUID
    675412.285642    4629    /usr/bin/ping    CAP_NET_RAW
    PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.

Listing capabilities used inside a container is more complicated, as tracing kernel calls is a very privileged operation. I wouldn't recommend using captrace from within, as this would require running your entire container and software with higher privileges (and poking holes in your MAC policy if you have one enforced). Instead, attach to it by PID from the outside, or, if you don't want to miss capabilities used at process initialisation, captrace the entire system from the outside and grep the output for the binary you're inspecting.

## Example

Let's strip a Docker container from most of the capabilities it gets by default, and start from scratch with a whitelist of actually required capabilities:

    # ./captrace | grep myservice &
    # docker run -d myservice:latest
    672484.966569    1086    /bin/myservice  CAP_CHOWN
    672484.968063    1086    /bin/myservice  CAP_NET_BIND_SERVICE
    672484.968623    1139    /bin/myservice  CAP_SETGID
    672484.968829    1139    /bin/myservice  CAP_SETUID
    # grep CapEff /proc/1086/status
    CapEff: 00000000a80425fb # (cap_chown, dac_override, fowner, net_raw, audit_write, etc. Way too much.)
    # docker run -d --cap-drop=all --cap-add chown --cap-add=net_bind_service --cap-add=setuid --cap-add=setgid myservice:latest

## Requirements

To build it, you need a compiler (ideally with `make`), and libc and Linux development headers. To compile a static version, you will probably need a static libc package.
To run it, you need a 4.4+ Linux kernel built with `CONFIG_KPROBE_EVENTS=y`, and a mounted `tracefs` filesystem. It's the default for recent Fedora, Debian and Arch distributions.

    git clone https://github.com/mtth-bfft/captrace
    cd captrace
    make # or make static

If you can't compile the binary version of this tool for your target machine, you can use a reduced `bash` version of this tool, which only supports attaching to existing processes and does not resolve capability names:

    sudo ./captrace.sh
    669161.938696   Xorg-1244      cap=0xf    userns=0xffffffff9a244660    audit=0x1
    669165.918900   Xorg-1244      cap=0xf    userns=0xffffffff9a244660    audit=0x1
    669166.394339   dmeventd-1003  cap=0x15   userns=0xffffffff9a244660    audit=0x1

## Contributing

If you find this tool useful, let me know which features you'd like to see in it. If you find bugs, please open an issue.
