# captrace

Lists capabilities used by processes at runtime, as they are requested, to assist in the task of creating custom hardened profiles for containers and sandboxes.
Tracing using [kprobes](https://www.kernel.org/doc/Documentation/kprobes.txt) heavily inspired by [capable](https://github.com/iovisor/bcc/blob/master/tools/capable.py).

## Usage

By default, all processes are displayed and audited capability checks are discarded (non-audited checks can be shown using `-v`):

    $ sudo ./captrace
    669161.938696   1244   /usr/libexec/Xorg   CAP_IPC_OWNER
    669165.918900   1244   /usr/libexec/Xorg   CAP_IPC_OWNER
    669166.394339   1003   /usr/sbin/dmeventd  CAP_SYS_ADMIN
    [...]

To list capabilities of a specific process, use `-p <pid>`. Add `-f` to also list capabilities used by new child processes. To list capabilities used by a command from its very start, use `captrace` followed by that command (but that will require running the command with elevated privileges):

    $ sudo ./captrace ping 127.0.0.1
    675412.284225    4629    /usr/bin/ping    CAP_SETUID
    675412.285642    4629    /usr/bin/ping    CAP_NET_RAW
    PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.

Listing capabilities used inside a container is more complicated, as tracing kernel calls is a very privileged operation. I wouldn't recommend using captrace from within, as this would require running your entire container and software with higher privileges (and poking holes in your MAC policy if you have one enforced). Instead, attach to it by PID from the outside, or, if you don't want to miss capabilities used at process initialisation, captrace the entire system from the outside and grep the output for the binary you're inspecting:

    $ sudo ./captrace | grep myservice &
    $ docker run -d myservice:latest
    672484.966569    1086    /bin/myservice  CAP_CHOWN
    672484.968063    1086    /bin/myservice  CAP_NET_BIND_SERVICE
    672484.968623    1139    /bin/myservice  CAP_SETGID
    672484.968829    1139    /bin/myservice  CAP_SETUID
    $ grep CapEff /proc/1086/status
    CapEff: 00000000a80425fb # <-- dac_override, fowner, etc. This will be better:
    $ docker run -d --cap-drop=all --cap-add chown --cap-add=net_bind_service --cap-add=setuid --cap-add=setgid myservice:latest

If you can't use a compiled version of the tool for your target machine, you can use the reduced `bash` version, which only supports attaching to existing processes and does not resolve capability names:

    $ sudo ./captrace.sh
    80720.360975    blueman-manager-888164  cap=0xc     opts=0x10
    80720.792573    blueman-manager-888164  cap=0xd     opts=0x0
    80721.068141    rpc-libvirtd-2509       cap=0x13    opts=0x0
    80727.273322    <...>-912085            cap=0xd     opts=0x0
    80733.270854    squid-279476            cap=0xc     opts=0x0

## Requirements

You need a Linux kernel built with `CONFIG_KPROBE_EVENTS=y`, and a mounted `tracefs` filesystem. It's the default for recent Fedora, Debian and Arch distributions.

Download the latest release, or build the tool with any C compiler (and optionally `make`) and libc and Linux development headers. To compile a static version, you will also need a static libc package.

    $ git clone https://github.com/mtth-bfft/captrace
    $ cd captrace
    $ make # or make static

## How this works

All kernel functions which check for privileges before performing an action end up calling, with a varying number of helpers in between, the same function `cap_capable(struct task_struct*, struct cred*, struct user_namespace*, cap_num)`.

That function is the only place where the user namespace tree is iterated
up until the root, or until a namespace grants access. Thus we only have
to monitor it using the built-in function tracepoint functionality.

Helpers include, at the time of writing:

```
- bpf_token_capable(struct bpf_token*, cap_num)
- sockopt_capable(cap_num)
    `-> capable(cap_num)
      - nsown_capable(cap_num)
      - task_ns_capable(struct task_struct*, cap_num)
      - sockopt_ns_capable(struct user_namespace*, cap_num)
      - capable_wrt_inode_uidgid(struct mnt_idmap*, struct inode*, cap_num)
          `-> ns_capable(struct user_namespace*, cap_num)
            - ns_capable_noaudit(struct user_namespace*, cap_num)
            - ns_capable_setid(struct user_namespace*, cap_num)
            - file_ns_capable(struct file*, struct user_namespace*, cap_num)
                `-> security_capable(struct user_namespace*, struct cred*, cap_num)

- has_capability(struct task_struct*, cap_num)
- has_ns_capability(struct task_struct*, cap_num)
    `-> security_real_capable(struct task_struct*, struct user_namespace*, cap_num)

- has_capability_noaudit(struct task_struct*, cap_num)
    `-> security_real_capable_noaudit(struct task_struct*, struct user_namespace*, cap_num)

- struct net* rtnl_link_get_net_capable(struct sk_buff*, struct net*, struct nlattr*[], cap_num)
- netlink_net_capable(struct sk_buff*, cap_num)
- netlink_capable(struct sk_buff*, cap_num)
    `-> netlink_ns_capable(struct sk_buff*, struct user_namespace*, cap_num)

- sk_net_capable(struct sock *sk, cap_num)
- sk_capable(struct sock *sk, cap_num)
    `-> sk_ns_capable(struct sock *sk, struct user_namespace *user_ns, cap_num)
```

The only subtlety is that `cap_capable` changed prototype in v3.3-RC1 with commit #[6a9de49](https://github.com/torvalds/linux/commit/6a9de49115d5ff9871d953af1a5c8249e1585731), and the semantics of its `audit` parameter changed too:

```C
int cap_capable(struct task_struct *tsk, const struct cred *cred, struct user_namespace *ns, int cap, int audit)
became:
int cap_capable(const struct cred *cred, struct user_namespace *ns, int cap, int audit)
```

So to have a cross-version userland tool, we fetch the 5 first call argument registers, and check whether the 3rd is a kernel pointer (>= 0xFFFF800000000000) to decide how to parse other arguments.

## Contributing

If you find this tool useful, let me know which features you'd like to see in it. If you find bugs, please open an issue.
