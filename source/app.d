module main;

import core.stdc.errno;
import core.stdc.string;
import core.sys.posix.fcntl;
import core.sys.posix.net.if_;
import core.sys.posix.sys.ioctl;
import core.sys.posix.unistd;
import std.stdio;
import std.string;

enum IFNAMSIZ = 16;
alias c_short = short;

enum
{
    // from <linux/if_tun.h>
    IFF_TUN = 0x0001,
    IFF_TAP = 0x0002,
    IFF_NO_PI = 0x1000,
    TUNSETIFF = 0x400454ca // _IOW('T', 202, int)
}

struct ifreq
{
    char[IFNAMSIZ] ifr_name;
    c_short ifr_flags;
}

int main()
{
    if (getuid() != 0)
    {
        stderr.writeln("Error: This program needs to run with administrative privileges.");
        return 1;
    }

    // Open TUN device
    int fd = open("/dev/net/tun".toStringz, O_RDWR);
    scope (exit)
        close(fd);

    if (fd < 0)
    {
        stderr.writeln("Error opening /dev/net/tun: ", errno);
        return 1;
    }

    ifreq ifr;
    memset(&ifr, 0, ifreq.sizeof);
    strncpy(ifr.ifr_name.ptr, cast(const char*)("tun0"), 4);

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    // Create interface
    if (ioctl(fd, TUNSETIFF, &ifr) < 0)
    {
        stderr.writeln("ioctl TUNSETIFF failed: ", errno);
        close(fd);
        return 1;
    }

    writeln("Created TUN device: ", cast(string) ifr.ifr_name);

    // TODO: Run in Docker container
    // TODO: Redirect traffic to the tun0

    ubyte[2000] buffer;
    while (true)
    {
        auto nread = read(fd, buffer.ptr, buffer.length);
        if (nread < 0)
        {
            if (errno != EINTR)
            {
                writeln("Error reading packet: ", errno);
                break;
            }
        }
        else
        {
            writeln("Read ", nread, " bytes from TUN device");
        }
    }

    // TODO: Revert routing changes and clean up

    return 0;
}
