use anyhow::{Context, Result};

#[cfg(any(
    target_os = "android",
    not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "android"
    ))
))]
use std::net::{Ipv6Addr, SocketAddr, UdpSocket};
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "ios"))]
use std::process::Command;

pub fn has_usable_ipv6_route() -> bool {
    has_usable_ipv6_route_inner().unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn has_usable_ipv6_route_inner() -> Result<bool> {
    let output = Command::new("ip")
        .args(["-6", "route", "get", "2001:4860:4860::8888"])
        .output()
        .context("execute ip -6 route get 2001:4860:4860::8888")?;
    if !output.status.success() {
        return Ok(false);
    }
    Ok(parse_linux_route_dev(&String::from_utf8_lossy(&output.stdout)).is_some())
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn has_usable_ipv6_route_inner() -> Result<bool> {
    let output = Command::new("route")
        .args(["-n", "get", "-inet6", "default"])
        .output()
        .context("execute route -n get -inet6 default")?;
    if !output.status.success() {
        return Ok(false);
    }
    Ok(parse_bsd_route_gateway(&String::from_utf8_lossy(&output.stdout)).is_some())
}

#[cfg(target_os = "android")]
fn has_usable_ipv6_route_inner() -> Result<bool> {
    probe_ipv6_udp_route()
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "ios",
    target_os = "android"
)))]
fn has_usable_ipv6_route_inner() -> Result<bool> {
    probe_ipv6_udp_route().or(Ok(false))
}

#[cfg(target_os = "linux")]
fn parse_linux_route_dev(output: &str) -> Option<String> {
    for line in output.lines() {
        let mut parts = line.split_whitespace();
        while let Some(part) = parts.next() {
            if part == "dev"
                && let Some(name) = parts.next()
                && !name.is_empty()
            {
                return Some(name.to_string());
            }
        }
    }
    None
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn parse_bsd_route_gateway(output: &str) -> Option<String> {
    for line in output.lines() {
        let Some(rest) = line.trim_start().strip_prefix("gateway:") else {
            continue;
        };
        let value = rest.trim();
        if value.is_empty() {
            continue;
        }
        let gateway = value.split_once('%').map_or(value, |(ip, _)| ip).trim();
        if !gateway.is_empty() {
            return Some(gateway.to_string());
        }
    }
    None
}

#[cfg(any(
    target_os = "android",
    not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "android"
    ))
))]
fn probe_ipv6_udp_route() -> Result<bool> {
    let socket = UdpSocket::bind(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0))
        .context("bind IPv6 UDP probe socket")?;
    Ok(socket
        .connect(SocketAddr::new(
            Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888).into(),
            53,
        ))
        .is_ok())
}

#[cfg(test)]
mod tests {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    use super::parse_bsd_route_gateway;
    #[cfg(target_os = "linux")]
    use super::parse_linux_route_dev;

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_linux_route_dev_extracts_interface_name() {
        let output =
            "2001:4860:4860::8888 from :: via fe80::1 dev eth0 proto ra metric 100 pref medium\n";
        assert_eq!(parse_linux_route_dev(output), Some("eth0".to_string()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_linux_route_dev_returns_none_without_interface() {
        let output = "unreachable 2001:4860:4860::8888 from :: metric 1024 error -101\n";
        assert_eq!(parse_linux_route_dev(output), None);
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    #[test]
    fn parse_bsd_route_gateway_extracts_gateway() {
        let output = "   route to: default\n destination: default\n    gateway: fe80::1%en0\n";
        assert_eq!(parse_bsd_route_gateway(output), Some("fe80::1".to_string()));
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    #[test]
    fn parse_bsd_route_gateway_returns_none_without_gateway() {
        let output = "   route to: default\n destination: default\n";
        assert_eq!(parse_bsd_route_gateway(output), None);
    }
}
