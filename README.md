# captrace

Lists capabilities used by processes on your system as they are requested, to assist in the task of creating custom hardened profiles for containers and sandboxes.
Inspired by [capable](https://github.com/iovisor/bcc/blob/master/tools/capable.py) but designed as a statically-linked binary with no dependency and minimal footprint.

You need a compiler and `make` to create the binary version. Using it requires a kernel with `CONFIG_EVENT_TRACING` and `CONFIG_KPROBE_EVENTS`. 

```
    git clone https://github.com/mtth-bfft/captrace
    make
    sudo ./captrace
    CAP_SYS_ADMIN      969   /usr/bin/dmeventd
    CAP_DAC_OVERRIDE   1028  /usr/bin/irqbalance
    CAP_NET_ADMIN      1251  /usr/bin/NetworkManager
    [...]
```

To list capabilities of an already running process, use `-p <pid>`. Add `-f` to also list capabilities used by child processes. *Support to launch a process and monitor it from the very start is a WIP, will be in the next release.*

If you don't want to copy any binary to the destination machine, or if it's running on some weird architecture, you can still use a `bash` (reduced) version of this tool, which only supports attaching to existing processes:

```
    sudo ./captrace.sh
    chromium-browse-27014 [003] .... 590087.217109: userns=0xffffffffab243e20 cap=0x15 audit=0x1
         irqbalance-1028  [001] .... 590100.166922: userns=0xffffffffab243e20 cap=0x1  audit=0x1
           dmeventd-969   [000] .... 590122.859654: userns=0xffffffffab243e20 cap=0x15 audit=0x1
```

## Contributing

If you find this tool useful, let me know which features you'd like to see in it. Pull requests welcome.
