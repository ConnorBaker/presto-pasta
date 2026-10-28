//! `netdev::host_has_ipv6_default_route` against the kernel's own
//! route and address dumps, and `netdev::configure` against
//! `Config::ipv6`. Each probe test sets up a namespace like a host the
//! rule has to judge (see the function's documentation), checks the
//! answer, then changes the one thing that decides it and checks that
//! the answer flips. Addresses meant to be usable are added with nodad,
//! so none is tentative by accident. Like `tests/connect_errors.rs`, the
//! tests need iproute2's `ip` and skip without unprivileged user
//! namespaces.

mod own_netns;

use std::process::Command;

use own_netns::{in_own_netns, ip};
use presto_pasta::Config;
use presto_pasta::netdev::{self, host_has_ipv6_default_route};

fn run(args: &str) {
    ip(args).unwrap_or_else(|e| panic!("{e}"));
}

/// What `ip` with `args` prints.
fn shown(args: &str) -> String {
    let out = Command::new("ip")
        .args(args.split_whitespace())
        .output()
        .unwrap_or_else(|e| panic!("ip {args}: {e}"));
    assert!(out.status.success(), "ip {args}: {}", out.status);
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A dummy interface, up, with only its link-local address.
const D0: &[&str] = &["link add d0 type dummy", "link set d0 up"];

#[test]
fn a_default_route_with_a_global_address_gives_ipv6() {
    let setup = [D0, &["-6 addr add 2001:db8:1::1/64 dev d0 nodad"]].concat();
    in_own_netns(
        "a_default_route_with_a_global_address_gives_ipv6",
        &setup,
        || {
            assert!(!host_has_ipv6_default_route(), "no default route yet");
            run("-6 route add default dev d0");
            assert!(host_has_ipv6_default_route());
        },
    );
}

/// IPv6 route, no IPv6 address at all: lo is down, so there is no
/// `::1` either, and d0 gets no link-local address.
#[test]
fn a_default_route_without_any_address_gives_none() {
    let setup = [
        "link add d0 type dummy",
        "link set d0 addrgenmode none",
        "link set d0 up",
        "-6 route add default dev d0",
    ];
    in_own_netns(
        "a_default_route_without_any_address_gives_none",
        &setup,
        || {
            assert!(!host_has_ipv6_default_route());
            run("-6 addr add 2001:db8:1::1/64 dev d0 nodad");
            assert!(host_has_ipv6_default_route());
        },
    );
}

#[test]
fn a_default_route_with_only_loopback_gives_none() {
    let setup = [
        "link set lo up",
        "link add d0 type dummy",
        "link set d0 addrgenmode none",
        "link set d0 up",
        "-6 route add default dev d0",
    ];
    in_own_netns(
        "a_default_route_with_only_loopback_gives_none",
        &setup,
        || {
            assert!(!host_has_ipv6_default_route());
            run("-6 addr add 2001:db8:1::1/64 dev d0 nodad");
            assert!(host_has_ipv6_default_route());
        },
    );
}

/// A router-advertised default route on a host whose address
/// configuration failed.
#[test]
fn a_default_route_with_only_link_local_gives_none() {
    let setup = [D0, &["-6 route add default dev d0"]].concat();
    in_own_netns(
        "a_default_route_with_only_link_local_gives_none",
        &setup,
        || {
            assert!(!host_has_ipv6_default_route());
            run("-6 addr add 2001:db8:1::1/64 dev d0 nodad");
            assert!(host_has_ipv6_default_route());
        },
    );
}

#[test]
fn a_deprecated_address_gives_none() {
    let setup = [
        D0,
        &[
            "-6 addr add 2001:db8:1::1/64 dev d0 nodad preferred_lft 0",
            "-6 route add default dev d0",
        ],
    ]
    .concat();
    in_own_netns("a_deprecated_address_gives_none", &setup, || {
        assert!(!host_has_ipv6_default_route());
        run("-6 addr change 2001:db8:1::1/64 dev d0 nodad preferred_lft forever");
        assert!(host_has_ipv6_default_route());
    });
}

/// A bridge without ports has no carrier, so duplicate address
/// detection never starts and the address stays tentative.
#[test]
fn a_tentative_address_gives_none() {
    let setup = [
        "link add br0 type bridge",
        "link set br0 up",
        "-6 addr add 2001:db8:1::1/64 dev br0",
        "-6 route add default dev br0",
    ];
    in_own_netns("a_tentative_address_gives_none", &setup, || {
        assert!(!host_has_ipv6_default_route());
        run("-6 addr add 2001:db8:1::2/64 dev br0 nodad");
        assert!(host_has_ipv6_default_route());
    });
}

#[test]
fn an_address_on_another_interface_gives_none() {
    let setup = [
        D0,
        &[
            "-6 addr add 2001:db8:1::1/64 dev d0 nodad",
            "link add d1 type dummy",
            "link set d1 up",
            "-6 route add default dev d1",
        ],
    ]
    .concat();
    in_own_netns("an_address_on_another_interface_gives_none", &setup, || {
        assert!(!host_has_ipv6_default_route());
        run("-6 addr add 2001:db8:2::1/64 dev d1 nodad");
        assert!(host_has_ipv6_default_route());
    });
}

#[test]
fn a_default_route_in_another_table_gives_none() {
    let setup = [
        D0,
        &[
            "-6 addr add 2001:db8:1::1/64 dev d0 nodad",
            "-6 route add default dev d0 table 52",
            "-6 rule add pref 5270 table 52",
        ],
    ]
    .concat();
    in_own_netns(
        "a_default_route_in_another_table_gives_none",
        &setup,
        || {
            assert!(!host_has_ipv6_default_route());
            run("-6 route add default dev d0");
            assert!(host_has_ipv6_default_route());
        },
    );
}

/// An unreachable default route is skipped, not taken as the first
/// default route: the kernel puts it on lo, which the probe passes over.
/// (That it is not unicast is checked only by the unit tests.)
#[test]
fn an_unreachable_default_route_gives_none() {
    let setup = [
        D0,
        &[
            "-6 addr add 2001:db8:1::1/64 dev d0 nodad",
            "-6 route add unreachable default",
        ],
    ]
    .concat();
    in_own_netns("an_unreachable_default_route_gives_none", &setup, || {
        assert!(!host_has_ipv6_default_route());
        run("-6 route add default dev d0 metric 2048");
        assert!(host_has_ipv6_default_route());
    });
}

/// The kernel lists default routes by metric, and the first decides.
#[test]
fn the_first_default_route_decides() {
    let setup = [
        D0,
        &[
            "link add d1 type dummy",
            "link set d1 up",
            "-6 addr add 2001:db8:1::1/64 dev d1 nodad",
            "-6 route add default dev d0 metric 100",
            "-6 route add default dev d1 metric 200",
        ],
    ]
    .concat();
    in_own_netns("the_first_default_route_decides", &setup, || {
        assert!(!host_has_ipv6_default_route());
        run("-6 route del default dev d0 metric 100");
        run("-6 route add default dev d0 metric 300");
        assert!(host_has_ipv6_default_route());
    });
}

/// A multipath route names its interfaces in next hops, not `RTA_OIF`.
#[test]
fn a_multipath_default_route_gives_ipv6() {
    let setup = [
        D0,
        &[
            "-6 addr add 2001:db8:1::1/64 dev d0 nodad",
            "link add d1 type dummy",
            "link set d1 up",
            "-6 addr add 2001:db8:2::1/64 dev d1 nodad",
        ],
    ]
    .concat();
    in_own_netns("a_multipath_default_route_gives_ipv6", &setup, || {
        assert!(!host_has_ipv6_default_route());
        run("-6 route add default nexthop via fe80::1 dev d0 nexthop via fe80::2 dev d1");
        assert!(host_has_ipv6_default_route());
    });
}

/// A host whose only IPv6 is an overlay network's, as Tailscale sets one
/// up: link-local addresses on the uplink (e0), and on the overlay's
/// interface (ov0) a /128 whose prefix route is the only main-table route
/// beyond the links, with the overlay's prefix and resolver routes in
/// another table, which a rule consults. No default route, so no IPv6;
/// one through ov0 would do.
#[test]
fn an_overlay_network_alone_gives_none() {
    let setup = [
        "link set lo up",
        "link add e0 type dummy",
        "link set e0 up",
        "link add ov0 type dummy",
        "link set ov0 up",
        "-6 addr add 2001:db8:100::5/128 dev ov0 nodad",
        "-6 route add 2001:db8:100::53/128 dev ov0 table 52",
        "-6 route add 2001:db8:100::/48 dev ov0 table 52",
        "-6 rule add pref 5270 table 52",
    ];
    in_own_netns("an_overlay_network_alone_gives_none", &setup, || {
        assert!(!host_has_ipv6_default_route());
        run("-6 route add default dev ov0");
        assert!(host_has_ipv6_default_route());
    });
}

/// `netdev::configure` gives the guest's interface IPv6 only with
/// `Config::ipv6`: cleared (d0), the interface gets its IPv4 address and
/// default route alone; set (d1, so nothing is left over from d0), also
/// `guest6` and a default route via `gateway6`.
#[test]
fn configure_gives_ipv6_only_with_config_ipv6() {
    in_own_netns(
        "configure_gives_ipv6_only_with_config_ipv6",
        &["link add d0 type dummy", "link add d1 type dummy"],
        || {
            let has_ipv4 = |dev: &str, cfg: &Config| {
                let addrs = shown(&format!("-4 addr show dev {dev}"));
                assert!(addrs.contains(&format!("inet {}/", cfg.guest4)), "{addrs}");
                let v4 = shown("-4 route show default");
                assert!(
                    v4.contains(&format!("via {} dev {dev}", cfg.gateway4)),
                    "{v4}"
                );
            };
            let cfg = Config {
                ipv6: false,
                ..Config::default()
            };
            netdev::configure("d0", &cfg).expect("configure d0 without IPv6");
            has_ipv4("d0", &cfg);
            let addrs = shown("-6 addr show dev d0 scope global");
            assert!(
                !addrs.contains("inet6"),
                "IPv6 address without Config::ipv6: {addrs}"
            );
            let routes = shown("-6 route show default");
            assert!(
                routes.is_empty(),
                "IPv6 default route without Config::ipv6: {routes}"
            );

            let cfg = Config { ipv6: true, ..cfg };
            netdev::configure("d1", &cfg).expect("configure d1 with IPv6");
            has_ipv4("d1", &cfg);
            let addrs = shown("-6 addr show dev d1 scope global");
            assert!(addrs.contains(&format!("{}/128", cfg.guest6)), "{addrs}");
            let routes = shown("-6 route show default");
            assert!(
                routes.contains(&format!("via {} dev d1", cfg.gateway6)),
                "{routes}"
            );
        },
    );
}
