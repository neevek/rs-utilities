use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use log::{debug, error, info};
use rustls::{OwnedTrustAnchor, RootCertStore};
use trust_dns_resolver::config::{
    LookupIpStrategy, NameServerConfig, NameServerConfigGroup, Protocol, ResolverConfig,
    ResolverOpts, ServerOrderingStrategy,
};
use trust_dns_resolver::error::{ResolveError, ResolveErrorKind};
use trust_dns_resolver::name_server::{
    GenericConnection, GenericConnectionProvider, RuntimeProvider, TokioRuntime,
};
use trust_dns_resolver::system_conf::read_system_conf;
use trust_dns_resolver::{AsyncResolver, TokioHandle};
use webpki_roots;

#[derive(PartialEq, Clone)]
pub enum DNSQueryOrdering {
    QueryStatistics,
    UserProvidedOrder,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DoTProvider {
    AliDNS,
    DNSPod,
    Google,
    NotSpecified,
}

impl DoTProvider {
    pub fn domain(&self) -> &'static str {
        match *self {
            DoTProvider::AliDNS => "dns.alidns.com",
            DoTProvider::DNSPod => "dot.pub",
            DoTProvider::Google => "dns.google",
            DoTProvider::NotSpecified => "none",
        }
    }
}

impl From<&str> for DoTProvider {
    fn from(s: &str) -> Self {
        match s {
            "alidns" => DoTProvider::AliDNS,
            "dnspod" => DoTProvider::DNSPod,
            "google" => DoTProvider::Google,
            _ => DoTProvider::NotSpecified,
        }
    }
}

pub struct DNSResolver<R: RuntimeProvider> {
    resolver: AsyncResolver<GenericConnection, GenericConnectionProvider<R>>,
}

pub type TokioDNSResolver = DNSResolver<TokioRuntime>;

pub async fn tokio_resolver(
    dot_provider: DoTProvider,
    dns_names: Vec<String>,
) -> Option<TokioDNSResolver> {
    tokio_resolver2(
        dot_provider,
        dns_names,
        3,
        DNSQueryOrdering::QueryStatistics,
    )
    .await
}

pub async fn tokio_resolver2(
    dot_provider: DoTProvider,
    dns_names: Vec<String>,
    num_conccurent_reqs: usize,
    ordering: DNSQueryOrdering,
) -> Option<TokioDNSResolver> {
    TokioDNSResolver::new(
        TokioHandle,
        dot_provider,
        dns_names,
        num_conccurent_reqs,
        ordering,
    )
    .await
}

impl<R: RuntimeProvider> DNSResolver<R> {
    pub async fn new(
        handle: R::Handle,
        dot_provider: DoTProvider,
        dns_names: Vec<String>,
        num_conccurent_reqs: usize,
        ordering: DNSQueryOrdering,
    ) -> Option<Self> {
        Some(DNSResolver {
            resolver: Self::create_async_resolver(
                handle,
                dot_provider,
                dns_names,
                num_conccurent_reqs,
                ordering,
            )
            .await
            .ok()?,
        })
    }

    pub async fn lookup(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let response = self.resolver.lookup_ip(domain).await?;
        let ips = response.iter().collect();
        debug!("resolved [{}] to {:?}", domain, ips);
        Ok(ips)
    }

    pub async fn lookup_first(&self, domain: &str) -> Result<IpAddr> {
        let response = self.resolver.lookup_ip(domain).await?;
        let ip = response
            .iter()
            .next()
            .context(format!("failed to resolve domain: {}", domain));
        debug!("resolved [{}] to {:?}", domain, ip);
        ip
    }

    async fn create_async_resolver(
        handle: R::Handle,
        dot_provider: DoTProvider,
        dns_names: Vec<String>,
        num_conccurent_reqs: usize,
        ordering: DNSQueryOrdering,
    ) -> Result<AsyncResolver<GenericConnection, GenericConnectionProvider<R>>, ResolveError> {
        let mut resolver_cfg = None;
        let dot_ips: _ = Self::resolve_dot_server(
            &handle,
            &dot_provider,
            &dns_names,
            num_conccurent_reqs,
            &ordering,
        )
        .await
        .map_err(|e| error!("resolving DoT server failed: {}", e))
        .unwrap_or_default();

        if !dot_ips.is_empty() {
            let ns_group_cfg = NameServerConfigGroup::from_ips_tls(
                &dot_ips,
                853,
                dot_provider.domain().to_string(),
                true,
            );

            let mut root_store = RootCertStore::empty();
            root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(
                |ta| {
                    OwnedTrustAnchor::from_subject_spki_name_constraints(
                        ta.subject,
                        ta.spki,
                        ta.name_constraints,
                    )
                },
            ));

            let client_config = rustls::ClientConfig::builder()
                .with_safe_default_cipher_suites()
                .with_safe_default_kx_groups()
                .with_protocol_versions(&[&rustls::version::TLS12])
                .unwrap()
                .with_root_certificates(root_store)
                .with_no_client_auth();

            let mut dot_resolver_cfg = ResolverConfig::from_parts(None, vec![], ns_group_cfg);
            dot_resolver_cfg.set_tls_client_config(Arc::new(client_config));
            resolver_cfg = Some(dot_resolver_cfg);

            info!("will use DoT server: {:?} -> {:?}", dot_provider, dot_ips);
        }

        // only when failing to use DoT server will normal name servers be used
        if resolver_cfg.is_none() {
            let mut normal_resolver_cfg = ResolverConfig::default();
            let count = Self::add_dns_servers(&mut normal_resolver_cfg, &dns_names);
            if count > 0 {
                resolver_cfg = Some(normal_resolver_cfg);
                info!(
                    "will use {} configured name servers: {:?}",
                    count, dns_names
                );
            }
        }

        if resolver_cfg.is_some() {
            AsyncResolver::<GenericConnection, GenericConnectionProvider<R>>::new(
                resolver_cfg.unwrap(),
                Self::create_resolver_conf(num_conccurent_reqs, &ordering),
                handle,
            )
        } else {
            Self::create_simple_async_resolver(
                handle.clone(),
                &vec![],
                num_conccurent_reqs,
                ordering.clone(),
            )
        }
    }

    async fn resolve_dot_server(
        handle: &R::Handle,
        dot_provider: &DoTProvider,
        dns_names: &[String],
        num_conccurent_reqs: usize,
        ordering: &DNSQueryOrdering,
    ) -> Result<Vec<IpAddr>, ResolveError> {
        if *dot_provider != DoTProvider::NotSpecified {
            // if DoT (DNS over TLS) is specified, a simple resolver is created to resolve the DoT domain first
            let tmp_resolver = Self::create_simple_async_resolver(
                handle.clone(),
                dns_names.as_ref(),
                num_conccurent_reqs,
                ordering.clone(),
            )
            .map_err(|e| ResolveErrorKind::Msg(e.to_string()))?;

            let dot_ips = tmp_resolver
                .lookup_ip(dot_provider.domain())
                .await?
                .iter()
                .collect::<Vec<IpAddr>>();

            Ok(dot_ips)
        } else {
            Ok(vec![])
        }
    }

    fn create_simple_async_resolver(
        handle: R::Handle,
        dns_names: &[String],
        num_conccurent_reqs: usize,
        ordering: DNSQueryOrdering,
    ) -> Result<AsyncResolver<GenericConnection, GenericConnectionProvider<R>>, ResolveError> {
        let mut resolver_cfg = ResolverConfig::new();
        let valid_domain_count = Self::add_dns_servers(&mut resolver_cfg, dns_names);
        if valid_domain_count > 0 {
            if let Ok(resolver) = AsyncResolver::new(
                resolver_cfg.clone(),
                Self::create_resolver_conf(num_conccurent_reqs, &ordering),
                handle.clone(),
            ) {
                return Ok(resolver);
            }
        }

        info!("will use system name servers");
        let (resolver_cfg, resolver_opt) =
            Self::create_resolver_system_conf(num_conccurent_reqs, &ordering)
                .map_err(|e| ResolveErrorKind::Msg(e.to_string()))?;

        AsyncResolver::<GenericConnection, GenericConnectionProvider<R>>::new(
            resolver_cfg,
            resolver_opt,
            handle,
        )
    }

    fn add_dns_servers(resolver_cfg: &mut ResolverConfig, dns_names: &[String]) -> usize {
        let mut valid_domain_count = 0;
        for domain in dns_names.iter() {
            if let Ok(ip) = format!("{}:53", domain).parse() {
                resolver_cfg.add_name_server(NameServerConfig::new(ip, Protocol::Udp));
                valid_domain_count += 1;
                info!("added dns server: {}", ip);
            }
        }
        valid_domain_count
    }

    fn create_resolver_conf(
        num_conccurent_reqs: usize,
        ordering: &DNSQueryOrdering,
    ) -> ResolverOpts {
        let mut resolver_opt = ResolverOpts::default();
        resolver_opt.timeout = Duration::from_secs(3);
        resolver_opt.ip_strategy = LookupIpStrategy::Ipv4thenIpv6;
        resolver_opt.attempts = 2;
        resolver_opt.num_concurrent_reqs = num_conccurent_reqs;
        resolver_opt.server_ordering_strategy = if ordering == &DNSQueryOrdering::UserProvidedOrder
        {
            ServerOrderingStrategy::UserProvidedOrder
        } else {
            ServerOrderingStrategy::QueryStatistics
        };

        resolver_opt
    }

    fn create_resolver_system_conf(
        num_conccurent_reqs: usize,
        ordering: &DNSQueryOrdering,
    ) -> Result<(ResolverConfig, ResolverOpts)> {
        let (resolver_cfg, mut resolver_opt) = read_system_conf()?;
        resolver_opt.timeout = Duration::from_secs(3);
        resolver_opt.ip_strategy = LookupIpStrategy::Ipv4thenIpv6;
        resolver_opt.attempts = 2;
        resolver_opt.num_concurrent_reqs = num_conccurent_reqs;
        resolver_opt.server_ordering_strategy = if ordering == &DNSQueryOrdering::UserProvidedOrder
        {
            ServerOrderingStrategy::UserProvidedOrder
        } else {
            ServerOrderingStrategy::QueryStatistics
        };

        Ok((resolver_cfg, resolver_opt))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_dns() {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let resolver = tokio_resolver2(
                    DoTProvider::AliDNS,
                    //DoTProvider::NotSpecified,
                    vec!["223.5.5.5".to_string()],
                    //vec![],
                    2,
                    DNSQueryOrdering::QueryStatistics,
                )
                .await
                .unwrap();

                let result = resolver.lookup("google.com").await.unwrap();
                info!("resolve result: {:?}", result);
            });
    }
}
