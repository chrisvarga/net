import fcntl
import os
import re
import socket
import struct
import ctypes
import array
import math

SYSFS_NET_PATH = b"/sys/class/net"
PROCFS_NET_PATH = b"/proc/net/dev"

# From linux/sockios.h
SIOCGIFCONF = 0x8912
SIOCGIFINDEX = 0x8933
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914
SIOCGIFHWADDR = 0x8927
SIOCSIFHWADDR = 0x8924
SIOCGIFADDR = 0x8915
SIOCSIFADDR = 0x8916
SIOCGIFNETMASK = 0x891B
SIOCSIFNETMASK = 0x891C
SIOCETHTOOL = 0x8946

# From linux/if.h
IFF_UP = 0x1

# From linux/socket.h
AF_UNIX = 1
AF_INET = 2

# From linux/ethtool.h
ETHTOOL_GSET = 0x00000001  # Get settings
ETHTOOL_SSET = 0x00000002  # Set settings
ETHTOOL_GLINK = 0x0000000A  # Get link status (ethtool_value)
ETHTOOL_SPAUSEPARAM = 0x00000013  # Set pause parameters.

ADVERTISED_10baseT_Half = 1 << 0
ADVERTISED_10baseT_Full = 1 << 1
ADVERTISED_100baseT_Half = 1 << 2
ADVERTISED_100baseT_Full = 1 << 3
ADVERTISED_1000baseT_Half = 1 << 4
ADVERTISED_1000baseT_Full = 1 << 5
ADVERTISED_Autoneg = 1 << 6
ADVERTISED_TP = 1 << 7
ADVERTISED_AUI = 1 << 8
ADVERTISED_MII = 1 << 9
ADVERTISED_FIBRE = 1 << 10
ADVERTISED_BNC = 1 << 11
ADVERTISED_10000baseT_Full = 1 << 12

# This is probably not cross-platform
SIZE_OF_IFREQ = 40

def up(ifname):
    """Bring up the bridge interface. Equivalent to ifconfig [iface] up."""
    sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Get existing device flags
    ifreq = struct.pack("16sh", bytes(ifname, "utf-8"), 0)
    flags = struct.unpack("16sh", fcntl.ioctl(sockfd, SIOCGIFFLAGS, ifreq))[1]

    # Set new flags
    flags = flags | IFF_UP
    ifreq = struct.pack("16sh", bytes(ifname, "utf-8"), flags)
    fcntl.ioctl(sockfd, SIOCSIFFLAGS, ifreq)


def down(ifname):
    """Bring down the bridge interface. Equivalent to ifconfig [iface] down."""
    sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Get existing device flags
    ifreq = struct.pack("16sh", bytes(ifname, "utf-8"), 0)
    flags = struct.unpack("16sh", fcntl.ioctl(sockfd, SIOCGIFFLAGS, ifreq))[1]

    # Set new flags
    flags = flags & ~IFF_UP
    ifreq = struct.pack("16sh", bytes(ifname, "utf-8"), flags)
    fcntl.ioctl(sockfd, SIOCSIFFLAGS, ifreq)


def is_up(ifname):
    """Return True if the interface is up, False otherwise."""
    sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Get existing device flags
    ifreq = struct.pack("16sh", bytes(ifname, "utf-8"), 0)
    flags = struct.unpack("16sh", fcntl.ioctl(sockfd, SIOCGIFFLAGS, ifreq))[1]

    # Set new flags
    if flags & IFF_UP:
        return True
    else:
        return False


def get_mac(ifname):
    """Obtain the device's mac address."""
    sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ifreq = struct.pack("16sH14s", bytes(ifname, "utf-8"), AF_UNIX, b"\x00" * 14)
    res = fcntl.ioctl(sockfd, SIOCGIFHWADDR, ifreq)
    address = struct.unpack("16sH14s", res)[2]
    mac = struct.unpack("6B8x", address)

    return ":".join(["%02X" % i for i in mac])


def set_mac(ifname, newmac):
    """Set the device's mac address. Device must be down for this to
    succeed."""
    sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    macbytes = [int(i, 16) for i in newmac.split(":")]
    ifreq = struct.pack("16sH6B8x", bytes(ifname, "utf-8"), AF_UNIX, *macbytes)
    fcntl.ioctl(sockfd, SIOCSIFHWADDR, ifreq)


def get_ip(ifname):
    sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ifreq = struct.pack("16sH14s", bytes(ifname, "utf-8"), AF_INET, b"\x00" * 14)
    try:
        res = fcntl.ioctl(sockfd, SIOCGIFADDR, ifreq)
    except IOError:
        return None
    ip = struct.unpack("16sH2x4s8x", res)[2]

    return socket.inet_ntoa(ip)


def set_ip(ifname, newip):
    sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ipbytes = socket.inet_aton(newip)
    ifreq = struct.pack(
        "16sH2s4s8s", bytes(ifname, "utf-8"), AF_INET, b"\x00" * 2, ipbytes, b"\x00" * 8
    )
    fcntl.ioctl(sockfd, SIOCSIFADDR, ifreq)


"""
def get_netmask(ifname):
    sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ifreq = struct.pack("16sH14s", bytes(ifname, "utf-8"), AF_INET, b"\x00" * 14)
    try:
        res = fcntl.ioctl(sockfd, SIOCGIFNETMASK, ifreq)
    except IOError:
        return 0
    netmask = socket.ntohl(struct.unpack("16sH2xI8x", res)[2])

    return 32 - int(round(math.log(ctypes.c_uint32(~netmask).value + 1, 2), 1))
"""


def get_netmask(ifname):
    return socket.inet_ntoa(
        fcntl.ioctl(
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM),
            SIOCGIFNETMASK,
            struct.pack("256s", bytes(ifname, "utf-8")),
        )[20:24]
    )


def set_netmask(ifname, netmask):
    sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    netmask = ctypes.c_uint32(~((2 ** (32 - netmask)) - 1)).value
    nmbytes = socket.htonl(netmask)
    ifreq = struct.pack(
        "16sH2sI8s", bytes(ifname, "utf-8"), AF_INET, b"\x00" * 2, nmbytes, b"\x00" * 8
    )
    fcntl.ioctl(sockfd, SIOCSIFNETMASK, ifreq)


def get_index(ifname):
    """Convert an interface name to an index value."""
    sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ifreq = struct.pack("16si", bytes(ifname, "utf-8"), 0)
    res = fcntl.ioctl(sockfd, SIOCGIFINDEX, ifreq)
    return struct.unpack("16si", res)[1]


def get_link_info(ifname):
    # First get link params
    sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ecmd = array.array("B", struct.pack("I39s", ETHTOOL_GSET, b"\x00" * 39))
    ifreq = struct.pack("16sP", bytes(ifname, "utf-8"), ecmd.buffer_info()[0])
    try:
        fcntl.ioctl(sockfd, SIOCETHTOOL, ifreq)
        res = ecmd.tobytes()
        speed, duplex, auto = struct.unpack("12xHB3xB24x", res)
    except IOError:
        speed, duplex, auto = 65535, 255, 255

    # Then get link up/down state
    ecmd = array.array("B", struct.pack("2I", ETHTOOL_GLINK, 0))
    ifreq = struct.pack("16sP", bytes(ifname, "utf-8"), ecmd.buffer_info()[0])
    fcntl.ioctl(sockfd, SIOCETHTOOL, ifreq)
    res = ecmd.tobytes()
    up = bool(struct.unpack("4xI", res)[0])

    if speed == 65535:
        speed = 0
    if duplex == 255:
        duplex = None
    else:
        duplex = bool(duplex)
    if auto == 255:
        auto = None
    else:
        auto = bool(auto)
    return speed, duplex, auto, up


def set_link_mode(ifname, speed, duplex):
    sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # First get the existing info
    ecmd = array.array("B", struct.pack("I39s", ETHTOOL_GSET, b"\x00" * 39))
    ifreq = struct.pack("16sP", bytes(ifname, "utf-8"), ecmd.buffer_info()[0])
    fcntl.ioctl(sockfd, SIOCETHTOOL, ifreq)
    # Then modify it to reflect our needs
    ecmd[0:4] = array.array("B", struct.pack("I", ETHTOOL_SSET))
    ecmd[12:14] = array.array("B", struct.pack("H", speed))
    ecmd[14] = int(duplex)
    ecmd[18] = 0  # Autonegotiation is off
    fcntl.ioctl(sockfd, SIOCETHTOOL, ifreq)


def set_link_auto(ifname, ten=True, hundred=True, thousand=True):
    sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # First get the existing info
    ecmd = array.array("B", struct.pack("I39s", ETHTOOL_GSET, b"\x00" * 39))
    ifreq = struct.pack("16sP", bytes(ifname, "utf-8"), ecmd.buffer_info()[0])
    fcntl.ioctl(sockfd, SIOCETHTOOL, ifreq)
    # Then modify it to reflect our needs
    ecmd[0:4] = array.array("B", struct.pack("I", ETHTOOL_SSET))

    advertise = 0
    if ten:
        advertise |= ADVERTISED_10baseT_Half | ADVERTISED_10baseT_Full
    if hundred:
        advertise |= ADVERTISED_100baseT_Half | ADVERTISED_100baseT_Full
    if thousand:
        advertise |= ADVERTISED_1000baseT_Half | ADVERTISED_1000baseT_Full

    newmode = struct.unpack("I", ecmd[4:8].tobytes())[0] & advertise
    ecmd[8:12] = array.array("B", struct.pack("I", newmode))
    ecmd[18] = 1
    fcntl.ioctl(sockfd, SIOCETHTOOL, ifreq)


def set_pause_param(ifname, autoneg, rx_pause, tx_pause):
    """
    Ethernet has flow control! The inter-frame pause can be adjusted, by
    auto-negotiation through an ethernet frame type with a simple two-field
    payload, and by setting it explicitly.

    http://en.wikipedia.org/wiki/Ethernet_flow_control
    """
    sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # create a struct ethtool_pauseparm
    # create a struct ifreq with its .ifr_data pointing at the above
    ecmd = array.array(
        "B",
        struct.pack(
            "IIII", ETHTOOL_SPAUSEPARAM, bool(autoneg), bool(rx_pause), bool(tx_pause)
        ),
    )
    buf_addr, _buf_len = ecmd.buffer_info()
    ifreq = struct.pack("16sP", bytes(ifname, "utf-8"), buf_addr)
    fcntl.ioctl(sockfd, SIOCETHTOOL, ifreq)


def get_stats(ifname):
    spl_re = re.compile(rb"\s+")

    fp = open(PROCFS_NET_PATH, "rb")
    # Skip headers
    fp.readline()
    fp.readline()
    while True:
        data = fp.readline()
        if not data:
            return None

        name, stats_str = data.split(b":")
        if name.strip() != ifname:
            continue

        stats = [int(a) for a in spl_re.split(stats_str.strip())]
        break

    titles = [
        "rx_bytes",
        "rx_packets",
        "rx_errs",
        "rx_drop",
        "rx_fifo",
        "rx_frame",
        "rx_compressed",
        "rx_multicast",
        "tx_bytes",
        "tx_packets",
        "tx_errs",
        "tx_drop",
        "tx_fifo",
        "tx_colls",
        "tx_carrier",
        "tx_compressed",
    ]
    return dict(list(zip(titles, stats)))


def iterifs(physical=True):
    """Iterate over all the interfaces in the system. If physical is
    true, then return only real physical interfaces (not 'lo', etc)."""
    sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    net_files = os.listdir(SYSFS_NET_PATH)
    interfaces = set()
    virtual = set()
    for d in net_files:
        path = os.path.join(SYSFS_NET_PATH, d)
        if not os.path.isdir(path):
            continue
        if not os.path.exists(os.path.join(path, b"device")):
            virtual.add(d)
        interfaces.add(d)

    # Some virtual interfaces don't show up in the above search, for example,
    # subinterfaces (e.g. eth0:1). To find those, we have to do an ioctl
    if not physical:
        # ifconfig gets a max of 30 interfaces. Good enough for us too.
        ifreqs = array.array("B", b"\x00" * SIZE_OF_IFREQ * 30)
        buf_addr, _buf_len = ifreqs.buffer_info()
        ifconf = struct.pack("iP", SIZE_OF_IFREQ * 30, buf_addr)
        ifconf_res = fcntl.ioctl(sockfd, SIOCGIFCONF, ifconf)
        ifreqs_len, _ = struct.unpack("iP", ifconf_res)

        assert ifreqs_len % SIZE_OF_IFREQ == 0, (
            "Unexpected amount of data returned from ioctl. "
            "You're probably running on an unexpected architecture"
        )

        res = ifreqs.tobytes()
        for i in range(0, ifreqs_len, SIZE_OF_IFREQ):
            d = res[i : i + 16].strip(b"\0")
            interfaces.add(d)

    results = interfaces - virtual if physical else interfaces
    return results


def findif(name, physical=True):
    for br in iterifs(physical):
        if name == br.name:
            return br
    return None


def list_ifs(physical=True):
    """Return a list of the names of the interfaces. If physical is
    true, then return only real physical interfaces (not 'lo', etc)."""
    return [br for br in iterifs(physical)]
