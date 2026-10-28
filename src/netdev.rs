//! Guest-side interface configuration.
//!
//! presto-pasta has no ARP/NDP responder and no DHCP: the tap
//! interface inside the sandbox namespace must carry the addresses
//! from [`Config`], default routes via the gateway addresses and
//! permanent neighbor entries for [`Config::gateway_mac`].
//! [`configure`] sets all of that up via ioctl and rtnetlink so
//! callers do not need an `ip` binary in the sandbox.

use std::io;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, OwnedFd};

use rustix::net::{
    AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType, netdevice, recv, send,
    socket_with,
};

use crate::Config;

/// MTU set on the tap interface: large frames let the guest emit GSO
/// aggregates that presto-pasta forwards as single writes.
pub const MTU: u32 = 65520;

#[expect(clippy::cast_possible_truncation, reason = "NLM_F_* fit in u16")]
const NLM_F_FLAGS: u16 =
    (libc::NLM_F_REQUEST | libc::NLM_F_ACK | libc::NLM_F_CREATE | libc::NLM_F_REPLACE) as u16;
/// A request for every object of a kind: a dump.
#[expect(clippy::cast_possible_truncation, reason = "NLM_F_* fit in u16")]
const NLM_F_DUMP_REQUEST: u16 = (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16;
/// `RTNH_F_ONLINK`: the gateway is reachable on the interface even
/// though it is outside the (host-width) address prefix.
const ONLINK: u32 = 0x4;
const RT_TABLE_MAIN: u8 = 254;
const RTPROT_BOOT: u8 = 3;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RTN_UNICAST: u8 = 1;
const NDA_DST: u16 = 1;

// Fixed-layout rtnetlink payload headers (linux/if_addr.h,
// linux/rtnetlink.h, linux/neighbour.h).
#[repr(C)]
struct IfAddrMsg {
    family: u8,
    prefixlen: u8,
    flags: u8,
    scope: u8,
    index: u32,
}

#[repr(C)]
struct RtMsg {
    family: u8,
    dst_len: u8,
    src_len: u8,
    tos: u8,
    table: u8,
    protocol: u8,
    scope: u8,
    rtype: u8,
    flags: u32,
}

#[repr(C)]
struct NdMsg {
    family: u8,
    pad1: u8,
    pad2: u16,
    ifindex: i32,
    state: u16,
    flags: u8,
    ntype: u8,
}

/// One rtnetlink request: a payload header followed by attributes,
/// serialized with the kernel's 4-byte alignment rules.
struct Request {
    buf: Vec<u8>,
}

impl Request {
    fn new<T>(msg_type: u16, header: &T) -> Self {
        Self::with_flags(msg_type, NLM_F_FLAGS, header)
    }

    fn with_flags<T>(msg_type: u16, flags: u16, header: &T) -> Self {
        let hdr_len = std::mem::size_of::<libc::nlmsghdr>();
        let mut buf = vec![0u8; hdr_len];
        // Written as bytes; nlmsg_len is fixed up in finish().
        let nl = libc::nlmsghdr {
            nlmsg_len: 0,
            nlmsg_type: msg_type,
            nlmsg_flags: flags,
            nlmsg_seq: 1,
            nlmsg_pid: 0,
        };
        buf[..hdr_len].copy_from_slice(unsafe {
            std::slice::from_raw_parts(std::ptr::from_ref(&nl).cast::<u8>(), hdr_len)
        });
        buf.extend_from_slice(unsafe {
            std::slice::from_raw_parts(std::ptr::from_ref(header).cast::<u8>(), size_of::<T>())
        });
        Self { buf }
    }

    fn attr(mut self, kind: u16, data: &[u8]) -> Self {
        while !self.buf.len().is_multiple_of(4) {
            self.buf.push(0);
        }
        #[expect(clippy::cast_possible_truncation, reason = "attributes are tiny")]
        let len = (4 + data.len()) as u16;
        self.buf.extend_from_slice(&len.to_ne_bytes());
        self.buf.extend_from_slice(&kind.to_ne_bytes());
        self.buf.extend_from_slice(data);
        self
    }

    fn finish(mut self) -> Vec<u8> {
        while !self.buf.len().is_multiple_of(4) {
            self.buf.push(0);
        }
        #[expect(clippy::cast_possible_truncation, reason = "requests are tiny")]
        let len = self.buf.len() as u32;
        self.buf[..4].copy_from_slice(&len.to_ne_bytes());
        self.buf
    }
}

fn ip_bytes(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

fn family(ip: IpAddr) -> u8 {
    #[expect(clippy::cast_possible_truncation, reason = "AF_INET(6) fit in u8")]
    match ip {
        IpAddr::V4(_) => libc::AF_INET as u8,
        IpAddr::V6(_) => libc::AF_INET6 as u8,
    }
}

/// Send one rtnetlink request and wait for its acknowledgement.
fn rtnetlink(sock: &OwnedFd, req: &[u8]) -> io::Result<()> {
    send(sock, req, SendFlags::empty())?;
    let mut buf = [0u8; 512];
    let (n, _) = recv(sock, &mut buf[..], RecvFlags::empty())?;
    let hdr_len = std::mem::size_of::<libc::nlmsghdr>();
    if n < hdr_len + 4 {
        return Err(io::Error::other("short netlink reply"));
    }
    let msg_type = u16::from_ne_bytes([buf[4], buf[5]]);
    if i32::from(msg_type) != libc::NLMSG_ERROR {
        return Err(io::Error::other("unexpected netlink reply type"));
    }
    let errno = i32::from_ne_bytes([
        buf[hdr_len],
        buf[hdr_len + 1],
        buf[hdr_len + 2],
        buf[hdr_len + 3],
    ]);
    if errno == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(-errno))
    }
}

/// Set `IFF_UP` and the MTU via `SIOCSIFFLAGS`/`SIOCSIFMTU`.
fn link_up(ifname: &str) -> io::Result<()> {
    let sock = socket_with(
        AddressFamily::INET,
        SocketType::DGRAM,
        SocketFlags::CLOEXEC,
        None,
    )?;
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    if ifname.len() >= ifr.ifr_name.len() {
        return Err(io::Error::other("interface name too long"));
    }
    unsafe {
        std::ptr::copy_nonoverlapping(
            ifname.as_ptr(),
            ifr.ifr_name.as_mut_ptr().cast::<u8>(),
            ifname.len(),
        );
    }
    if unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFFLAGS, &mut ifr) } < 0 {
        return Err(io::Error::last_os_error());
    }
    unsafe {
        #[expect(
            clippy::cast_possible_truncation,
            reason = "IFF_UP|IFF_RUNNING fit in c_short"
        )]
        {
            ifr.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
        }
        if libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFFLAGS, &ifr) < 0 {
            return Err(io::Error::last_os_error());
        }
        ifr.ifr_ifru.ifru_mtu = MTU.cast_signed();
        if libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFMTU, &ifr) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn add_addr(sock: &OwnedFd, ifindex: u32, ip: IpAddr) -> io::Result<()> {
    let hdr = IfAddrMsg {
        family: family(ip),
        prefixlen: if ip.is_ipv4() { 32 } else { 128 },
        #[expect(clippy::cast_possible_truncation, reason = "IFA_F_NODAD fits in u8")]
        flags: if ip.is_ipv4() {
            0
        } else {
            libc::IFA_F_NODAD as u8
        },
        scope: RT_SCOPE_UNIVERSE,
        index: ifindex,
    };
    let req = Request::new(libc::RTM_NEWADDR, &hdr)
        .attr(libc::IFA_LOCAL, &ip_bytes(ip))
        .attr(libc::IFA_ADDRESS, &ip_bytes(ip))
        .finish();
    rtnetlink(sock, &req)
}

fn add_default_route(sock: &OwnedFd, ifindex: u32, gateway: IpAddr) -> io::Result<()> {
    let hdr = RtMsg {
        family: family(gateway),
        dst_len: 0,
        src_len: 0,
        tos: 0,
        table: RT_TABLE_MAIN,
        protocol: RTPROT_BOOT,
        scope: RT_SCOPE_UNIVERSE,
        rtype: RTN_UNICAST,
        flags: ONLINK,
    };
    let req = Request::new(libc::RTM_NEWROUTE, &hdr)
        .attr(libc::RTA_GATEWAY, &ip_bytes(gateway))
        .attr(libc::RTA_OIF, &ifindex.to_ne_bytes())
        .finish();
    rtnetlink(sock, &req)
}

fn add_neighbor(sock: &OwnedFd, ifindex: u32, gateway: IpAddr, mac: [u8; 6]) -> io::Result<()> {
    let hdr = NdMsg {
        family: family(gateway),
        pad1: 0,
        pad2: 0,
        #[expect(clippy::cast_possible_wrap, reason = "kernel ifindexes are small")]
        ifindex: ifindex as i32,
        state: libc::NUD_PERMANENT,
        flags: 0,
        ntype: 0,
    };
    let req = Request::new(libc::RTM_NEWNEIGH, &hdr)
        .attr(NDA_DST, &ip_bytes(gateway))
        .attr(libc::NDA_LLADDR, &mac)
        .finish();
    rtnetlink(sock, &req)
}

/// The loopback interface's index, which Linux fixes at 1
/// (`LOOPBACK_IFINDEX`, include/net/flow.h).
const LOOPBACK_IFINDEX: u32 = 1;

/// An IPv6 route of the namespace, as much of it as
/// [`gives_ipv6`] needs.
#[derive(Clone, Copy, Debug)]
struct Route {
    /// `RTA_TABLE`: the routing table, e.g. `RT_TABLE_MAIN`.
    table: u32,
    /// `rtm_type`: unicast, local, unreachable, ...
    rtype: u8,
    /// `rtm_dst_len`: 0 for a default route.
    dst_len: u8,
    /// `RTA_OIF`, or the first next hop's interface of a multipath
    /// route; 0 without either.
    oif: u32,
}

/// An IPv6 address of the namespace, as much of it as
/// [`gives_ipv6`] needs.
#[derive(Clone, Copy, Debug)]
struct Addr {
    /// `ifa_index`: the interface it is on.
    ifindex: u32,
    /// `ifa_scope`: universe for global and ULA addresses, link for
    /// `fe80::/10`, host for `::1`.
    scope: u8,
    /// `IFA_FLAGS`: `IFA_F_*`.
    flags: u32,
}

/// Whether the current network namespace has an IPv6 default route
/// it can use: the first unicast default route of the main table
/// leaves through an interface other than loopback that has an IPv6
/// address of scope below link (global or ULA), neither deprecated nor
/// tentative. False when the routes or addresses cannot be read, e.g.
/// without IPv6.
///
/// Intended for [`Config::ipv6`], called in the namespace the
/// datapath's host sockets live in before the guest is configured.
///
/// It asks what pasta asks before taking IPv6 from a host interface
/// (passt at commit 6aa4f88): `nl_get_ext_if` picks the interface of
/// the first such default route, failing one that of the first other
/// route not to a link-local prefix, and `conf_ip6` takes IPv6 from it
/// when it has an address that is not deprecated and has a scope below
/// link. Where pasta takes IPv6 from a default route's interface and
/// configures its guest's interface itself (`--config-net`, as
/// [`configure`] does), its guest gets that interface's addresses and
/// routes, a default route among them, and this answers true.
///
/// Elsewhere this answers false, and the caller's guest gets no IPv6
/// where pasta's still gets some:
/// - from an interface without a default route, an overlay network's
///   say, pasta copies the routes, which [`Config::ipv6`] cannot
///   express;
/// - with no interface to take IPv6 from, pasta's local mode gives its
///   guest no global address and a default route via `fe80::1`.
///
/// (Without `--config-net`, pasta's router advertisements give its
/// guest a default route in both cases.) A default route is all
/// presto-pasta's guest could get, and its host could serve it at most
/// for an overlay's prefix: the guest's other TCP connects to IPv6 fail
/// at once, but it still tries IPv6 first (RFC 6724), and its UDP waits
/// out timeouts, since "no route" is a soft error to a UDP socket.
///
/// pasta also needs a link-local address on the interface, or a
/// link-local gateway, because it answers the guest from it;
/// presto-pasta answers from [`Config::gateway6`] and does not. pasta
/// does not check for tentative addresses; this does, since the kernel
/// never picks one as a source (RFC 4862 5.4, `__ipv6_dev_get_saddr`,
/// which excepts optimistic DAD where this does not), and without a
/// source a guest connect would go unanswered.
#[must_use]
pub fn host_has_ipv6_default_route() -> bool {
    #[expect(clippy::cast_possible_truncation, reason = "AF_INET6 fits in u8")]
    let family = libc::AF_INET6 as u8;
    let rtm = RtMsg {
        family,
        dst_len: 0,
        src_len: 0,
        tos: 0,
        table: 0,
        protocol: 0,
        scope: 0,
        rtype: 0,
        flags: 0,
    };
    let ifa = IfAddrMsg {
        family,
        prefixlen: 0,
        flags: 0,
        scope: 0,
        index: 0,
    };
    let mut routes = Vec::new();
    let mut addrs = Vec::new();
    let dumped = rtnetlink_dump(
        &Request::with_flags(libc::RTM_GETROUTE, NLM_F_DUMP_REQUEST, &rtm).finish(),
        libc::RTM_NEWROUTE,
        |msg| routes.extend(parse_route(msg)),
    )
    .and_then(|()| {
        rtnetlink_dump(
            &Request::with_flags(libc::RTM_GETADDR, NLM_F_DUMP_REQUEST, &ifa).finish(),
            libc::RTM_NEWADDR,
            |msg| addrs.extend(parse_addr(msg)),
        )
    });
    dumped.is_ok() && gives_ipv6(&routes, &addrs)
}

/// [`host_has_ipv6_default_route`] over the namespace's IPv6 routes and
/// addresses, in the kernel's dump order.
fn gives_ipv6(routes: &[Route], addrs: &[Addr]) -> bool {
    // pasta also skips routes to link-local prefixes, which a default
    // route is not.
    let Some(oif) = routes
        .iter()
        .find(|r| {
            r.table == u32::from(RT_TABLE_MAIN)
                && r.rtype == RTN_UNICAST
                && r.dst_len == 0
                && r.oif != 0
                && r.oif != LOOPBACK_IFINDEX
        })
        .map(|r| r.oif)
    else {
        return false;
    };
    addrs.iter().any(|a| {
        a.ifindex == oif
            && a.scope < libc::RT_SCOPE_LINK
            && a.flags & (libc::IFA_F_DEPRECATED | libc::IFA_F_TENTATIVE) == 0
    })
}

/// Send the dump request `req` on a new rtnetlink socket and pass the
/// payload of every reply of type `reply` to `each`, up to the kernel's
/// `NLMSG_DONE`.
fn rtnetlink_dump(req: &[u8], reply: u16, mut each: impl FnMut(&[u8])) -> io::Result<()> {
    let sock = socket_with(
        AddressFamily::NETLINK,
        SocketType::RAW,
        SocketFlags::CLOEXEC,
        None,
    )?;
    send(&sock, req, SendFlags::empty())?;
    let hdr_len = std::mem::size_of::<libc::nlmsghdr>();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        // TRUNC: a reply longer than the buffer is an error, not cut.
        let (n, len) = recv(&sock, &mut buf[..], RecvFlags::TRUNC)?;
        if len > n {
            return Err(io::Error::other("netlink reply longer than the buffer"));
        }
        let mut msgs = &buf[..n];
        while msgs.len() >= hdr_len {
            let len = u32_at(msgs, 0)
                .and_then(|l| usize::try_from(l).ok())
                .unwrap_or(0);
            if len < hdr_len || len > msgs.len() {
                return Err(io::Error::other("malformed netlink reply"));
            }
            let msg_type = u16::from_ne_bytes([msgs[4], msgs[5]]);
            let payload = &msgs[hdr_len..len];
            match i32::from(msg_type) {
                // Both carry an errno, 0 or negative.
                libc::NLMSG_DONE | libc::NLMSG_ERROR => {
                    return match u32_at(payload, 0).map(u32::cast_signed) {
                        Some(0) => Ok(()),
                        Some(errno) => Err(io::Error::from_raw_os_error(-errno)),
                        None => Err(io::Error::other("malformed netlink reply")),
                    };
                }
                _ if msg_type == reply => each(payload),
                _ => {}
            }
            msgs = &msgs[len.next_multiple_of(4).min(msgs.len())..];
        }
    }
}

/// The native-endian `u32` at `at` in `bytes`.
fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

/// The attributes, as (type, data), of an rtnetlink payload whose fixed
/// header is `header_len` bytes long.
fn attrs(payload: &[u8], header_len: usize) -> impl Iterator<Item = (u16, &[u8])> {
    let mut rest = payload.get(header_len..).unwrap_or_default();
    std::iter::from_fn(move || {
        let len = usize::from(u16::from_ne_bytes([*rest.first()?, *rest.get(1)?]));
        let kind = u16::from_ne_bytes([*rest.get(2)?, *rest.get(3)?]);
        let data = rest.get(4..len)?;
        rest = rest.get(len.next_multiple_of(4)..).unwrap_or_default();
        // NLA_TYPE_MASK: without the nested and byte-order flags.
        Some((kind & 0x3fff, data))
    })
}

/// An IPv6 route from the payload of an `RTM_NEWROUTE` message.
fn parse_route(payload: &[u8]) -> Option<Route> {
    // struct rtmsg: family, dst_len, src_len, tos, table, protocol,
    // scope, type, flags
    let hdr = payload.get(..size_of::<RtMsg>())?;
    if i32::from(hdr[0]) != libc::AF_INET6 {
        return None;
    }
    let mut route = Route {
        table: u32::from(hdr[4]),
        rtype: hdr[7],
        dst_len: hdr[1],
        oif: 0,
    };
    for (kind, data) in attrs(payload, size_of::<RtMsg>()) {
        match kind {
            libc::RTA_TABLE => route.table = u32_at(data, 0)?,
            libc::RTA_OIF => route.oif = u32_at(data, 0)?,
            // struct rtnexthop: len, flags, hops, ifindex
            libc::RTA_MULTIPATH => route.oif = u32_at(data, 4)?,
            _ => {}
        }
    }
    Some(route)
}

/// An IPv6 address from the payload of an `RTM_NEWADDR` message.
fn parse_addr(payload: &[u8]) -> Option<Addr> {
    // struct ifaddrmsg: family, prefixlen, flags, scope, index
    let hdr = payload.get(..size_of::<IfAddrMsg>())?;
    if i32::from(hdr[0]) != libc::AF_INET6 {
        return None;
    }
    let mut addr = Addr {
        ifindex: u32_at(hdr, 4)?,
        scope: hdr[3],
        flags: u32::from(hdr[2]),
    };
    for (kind, data) in attrs(payload, size_of::<IfAddrMsg>()) {
        if kind == libc::IFA_FLAGS {
            addr.flags = u32_at(data, 0)?;
        }
    }
    Some(addr)
}

/// Configure the tap interface inside the sandbox namespace to match
/// `cfg`: link up with a large MTU, the guest addresses (host-width
/// prefixes), onlink default routes via the gateway addresses and
/// permanent neighbor entries for the gateway MAC; IPv6 only with
/// [`Config::ipv6`]. Must run in the namespace that owns the
/// interface, with `CAP_NET_ADMIN` there.
///
/// # Errors
///
/// Any ioctl or rtnetlink failure, e.g. when the interface does not
/// exist or the caller lacks `CAP_NET_ADMIN`.
pub fn configure(ifname: &str, cfg: &Config) -> io::Result<()> {
    link_up(ifname)?;
    let inet = socket_with(
        AddressFamily::INET,
        SocketType::DGRAM,
        SocketFlags::CLOEXEC,
        None,
    )?;
    let ifindex = netdevice::name_to_index(&inet, ifname)?;

    // NETLINK_ROUTE is rustix's default netlink protocol.
    let sock = socket_with(
        AddressFamily::NETLINK,
        SocketType::RAW,
        SocketFlags::CLOEXEC,
        None,
    )?;
    for (guest, gateway) in [
        (IpAddr::V4(cfg.guest4), IpAddr::V4(cfg.gateway4)),
        (IpAddr::V6(cfg.guest6), IpAddr::V6(cfg.gateway6)),
    ] {
        if guest.is_ipv6() && !cfg.ipv6 {
            continue;
        }
        add_addr(&sock, ifindex, guest)?;
        add_neighbor(&sock, ifindex, gateway, cfg.gateway_mac)?;
        add_default_route(&sock, ifindex, gateway)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Addr, Route, gives_ipv6};

    const MAIN: u32 = 254;
    const LO: u32 = 1;
    const ETH0: u32 = 2;
    const ETH1: u32 = 3;
    const UNICAST: u8 = 1;
    // linux/rtnetlink.h, linux/if_addr.h
    const RTN_LOCAL: u8 = 2;
    const RTN_UNREACHABLE: u8 = 7;
    const SCOPE_UNIVERSE: u8 = 0;
    const SCOPE_LINK: u8 = 253;
    const SCOPE_HOST: u8 = 254;
    const PERMANENT: u32 = 0x80;
    const OPTIMISTIC: u32 = 0x04;
    const DADFAILED: u32 = 0x08;
    const DEPRECATED: u32 = 0x20;
    const TENTATIVE: u32 = 0x40;

    fn route(table: u32, rtype: u8, dst_len: u8, oif: u32) -> Route {
        Route {
            table,
            rtype,
            dst_len,
            oif,
        }
    }

    fn default_route(oif: u32) -> Route {
        route(MAIN, UNICAST, 0, oif)
    }

    fn addr(ifindex: u32, scope: u8, flags: u32) -> Addr {
        Addr {
            ifindex,
            scope,
            flags,
        }
    }

    /// A global (or ULA: both have universe scope) address on `ifindex`.
    fn global(ifindex: u32) -> Addr {
        addr(ifindex, SCOPE_UNIVERSE, PERMANENT)
    }

    #[test]
    fn a_default_route_with_a_global_address_gives_ipv6() {
        assert!(gives_ipv6(&[default_route(ETH0)], &[global(ETH0)]));
        // the other addresses an interface has do not matter
        let ll = addr(ETH0, SCOPE_LINK, PERMANENT);
        assert!(gives_ipv6(&[default_route(ETH0)], &[ll, global(ETH0)]));
    }

    /// A host whose only IPv6 is an overlay network's, as Tailscale sets
    /// one up: the uplink (2) has link-local addresses only, the overlay
    /// interface (3) a /128 whose prefix route is the only main-table
    /// route beyond the links, and the overlay's prefix and resolver
    /// routes are in another table, which a rule consults. pasta takes
    /// the overlay interface as its template there, so its guest gets
    /// the /128 and no default route; this gives no IPv6.
    #[test]
    fn an_overlay_network_alone_gives_none() {
        let routes = [
            route(52, UNICAST, 128, ETH1),
            route(52, UNICAST, 48, ETH1),
            route(MAIN, UNICAST, 128, ETH1),
            route(MAIN, UNICAST, 64, ETH0),
            route(MAIN, UNICAST, 64, ETH1),
            route(255, RTN_LOCAL, 128, LO),
            route(255, RTN_LOCAL, 128, ETH1),
        ];
        let addrs = [
            addr(LO, SCOPE_HOST, PERMANENT),
            addr(ETH0, SCOPE_LINK, PERMANENT),
            global(ETH1),
            addr(ETH1, SCOPE_LINK, PERMANENT),
        ];
        assert!(!gives_ipv6(&routes, &addrs));
    }

    #[test]
    fn only_a_default_route_counts() {
        // an on-link prefix of the interface's address
        let prefix = route(MAIN, UNICAST, 64, ETH0);
        assert!(!gives_ipv6(&[prefix], &[global(ETH0)]));
        // a default route in another table, as a rule could consult
        assert!(!gives_ipv6(&[route(52, UNICAST, 0, ETH0)], &[global(ETH0)]));
        // not unicast: unreachable (on lo, as the kernel puts it), or
        // local on the interface itself
        let unreachable = route(MAIN, RTN_UNREACHABLE, 0, LO);
        assert!(!gives_ipv6(&[unreachable], &[global(ETH0), global(LO)]));
        assert!(!gives_ipv6(
            &[route(MAIN, RTN_LOCAL, 0, ETH0)],
            &[global(ETH0)]
        ));
        assert!(!gives_ipv6(&[], &[global(ETH0)]));
    }

    #[test]
    fn the_route_needs_a_usable_address_on_its_interface() {
        let routes = [default_route(ETH0)];
        // none at all
        assert!(!gives_ipv6(&routes, &[]));
        // only ::1
        assert!(!gives_ipv6(&routes, &[addr(LO, SCOPE_HOST, PERMANENT)]));
        // only link-local, as a router-advertised default route leaves
        // a host whose address configuration failed
        assert!(!gives_ipv6(&routes, &[addr(ETH0, SCOPE_LINK, PERMANENT)]));
        // host scope on the interface itself
        assert!(!gives_ipv6(&routes, &[addr(ETH0, SCOPE_HOST, PERMANENT)]));
        // a global address on another interface
        assert!(!gives_ipv6(&routes, &[global(ETH1)]));
        // deprecated (preferred lifetime over)
        assert!(!gives_ipv6(
            &routes,
            &[addr(ETH0, SCOPE_UNIVERSE, DEPRECATED)]
        ));
        // tentative: in duplicate address detection, also optimistic,
        // or failed it
        for flags in [TENTATIVE, TENTATIVE | OPTIMISTIC, TENTATIVE | DADFAILED] {
            let a = addr(ETH0, SCOPE_UNIVERSE, PERMANENT | flags);
            assert!(!gives_ipv6(&routes, &[a]), "{flags:#x}");
        }
    }

    #[test]
    fn the_first_default_route_decides() {
        assert!(!gives_ipv6(
            &[default_route(ETH0), default_route(ETH1)],
            &[global(ETH1)]
        ));
        assert!(gives_ipv6(
            &[default_route(ETH1), default_route(ETH0)],
            &[global(ETH1)]
        ));
    }

    /// Routes pasta skips do not decide: one without an interface (a
    /// nexthop object's, when the kernel does not expand it) and one
    /// through lo.
    #[test]
    fn skipped_routes_do_not_decide() {
        for skipped in [0, LO] {
            let routes = [default_route(skipped), default_route(ETH0)];
            assert!(
                gives_ipv6(&routes, &[global(LO), global(ETH0)]),
                "{skipped}"
            );
            assert!(!gives_ipv6(&routes, &[global(LO)]), "{skipped}");
        }
    }
}
