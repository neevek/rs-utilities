use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use log::{debug, error, info};
use rustls::{OwnedTrustAnchor, RootCertStore};
use trust_dns_resolver::config::{
    LookupIpStrategy, NameServerConfig, NameServerConfigGroup, Protocol, ResolverConfig,
    ResolverOpts, ServerOrderingStrategy,
};
use trust_dns_resolver::error::{ResolveError, ResolveErrorKind};
use trust_dns_resolver::name_server::ConnectionProvider;
use trust_dns_resolver::system_conf::read_system_conf;
use trust_dns_resolver::AsyncResolver;
use webpki_roots;

#[derive(PartialEq, Clone)]
pub enum DNSQueryOrdering {
    QueryStatistics,
    UserProvidedOrder,
}

#[derive(PartialEq, Clone)]
pub enum DNSResolverType {
    DoT,
    UserProvided,
    System,
}

impl ToString for DNSResolverType {
    fn to_string(&self) -> String {
        match &self {
            Self::DoT => "DoT".to_string(),
            Self::UserProvided => "UserProvided".to_string(),
            Self::System => "System".to_string(),
        }
    }
}

pub struct DNSResolver {
    resolver: DynAsyncDNSResolver,
    resolver_type: DNSResolverType,
}

impl DNSResolver {
    fn new(resolver: DynAsyncDNSResolver, resolver_type: DNSResolverType) -> Self {
        Self {
            resolver,
            resolver_type,
        }
    }

    pub async fn lookup(&self, domain: &str) -> Result<Vec<IpAddr>> {
        self.resolver.lookup(domain).await
    }

    pub async fn lookup_first(&self, domain: &str) -> Result<IpAddr> {
        self.resolver.lookup_first(domain).await
    }

    pub fn resolver_type(&self) -> DNSResolverType {
        self.resolver_type.clone()
    }
}

type DynAsyncDNSResolver = Box<dyn AsyncDNSResolver + Send + Sync>;

#[async_trait]
trait AsyncDNSResolver {
    async fn lookup(&self, domain: &str) -> Result<Vec<IpAddr>>;
    async fn lookup_first(&self, domain: &str) -> Result<IpAddr>;
}

struct SimpleTokioResolver;

fn ensure_port(domain: &str) -> Option<String> {
    if domain.rfind(':').is_none() {
        // tokio::net::lookup_host() accepts domain:port pair, but we only want IP,
        // a random port is used here
        Some(domain.to_owned() + ":80")
    } else {
        None
    }
}

#[async_trait]
impl AsyncDNSResolver for SimpleTokioResolver {
    async fn lookup(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let domain_with_port = ensure_port(domain);
        let domain = if domain_with_port.is_some() {
            domain_with_port.as_ref().unwrap().as_str()
        } else {
            domain
        };
        let ips = tokio::net::lookup_host(domain)
            .await
            .context(format!("failed to resolve domain: {}", domain))?
            .map(|e| e.ip())
            .collect();
        debug!("resolved [{}] to {:?}", domain, ips);
        Ok(ips)
    }

    async fn lookup_first(&self, domain: &str) -> Result<IpAddr> {
        let domain_with_port = ensure_port(domain);
        let domain = if domain_with_port.is_some() {
            domain_with_port.as_ref().unwrap().as_str()
        } else {
            domain
        };
        let ip = tokio::net::lookup_host(domain)
            .await
            .context(format!("failed to resolve domain: {}", domain))?
            .next()
            .map(|e| e.ip())
            .context(format!(
                "failed to obtain first resolved ip for domain: {}",
                domain
            ))?;
        debug!("resolved [{}] to {:?}", domain, ip);
        Ok(ip)
    }
}

#[async_trait]
impl<R: ConnectionProvider> AsyncDNSResolver for AsyncResolver<R> {
    async fn lookup(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let response = self.lookup_ip(domain).await.map_err(|e| {
            error!("failed to resolve domain: {}, error: {}", domain, e);
            e
        })?;
        let ips = response.iter().collect();
        debug!("resolved [{}] to {:?}", domain, ips);
        Ok(ips)
    }

    async fn lookup_first(&self, domain: &str) -> Result<IpAddr> {
        let response = self.lookup_ip(domain).await?;
        let ip = response
            .iter()
            .next()
            .context(format!("failed to resolve domain: {}", domain));
        debug!("resolved [{}] to {:?}", domain, ip);
        ip
    }
}

pub async fn resolver(dot_provider: &str, dns_names: Vec<String>) -> DNSResolver {
    resolver2(
        dot_provider,
        dns_names,
        3,
        DNSQueryOrdering::QueryStatistics,
    )
    .await
}

pub async fn resolver2(
    dot_provider: &str,
    dns_names: Vec<String>,
    num_conccurent_reqs: usize,
    ordering: DNSQueryOrdering,
) -> DNSResolver {
    if let Ok(resolver) = DNSResolverHelper::create_async_resolver(
        dot_provider,
        dns_names,
        num_conccurent_reqs,
        ordering.clone(),
    )
    .await
    {
        resolver
    } else {
        info!("fall back to use system resolver!");
        system_resolver(num_conccurent_reqs, ordering)
    }
}

pub fn system_resolver(num_conccurent_reqs: usize, ordering: DNSQueryOrdering) -> DNSResolver {
    DNSResolver::new(
        DNSResolverHelper::create_system_resolver(num_conccurent_reqs, ordering),
        DNSResolverType::System,
    )
}

struct DNSResolverHelper;
impl DNSResolverHelper {
    async fn create_async_resolver(
        dot_provider: &str,
        dns_names: Vec<String>,
        num_conccurent_reqs: usize,
        ordering: DNSQueryOrdering,
    ) -> Result<DNSResolver, ResolveError> {
        let mut resolver_cfg = None;
        let dot_ips: _ =
            Self::resolve_dot_server(&dot_provider, &dns_names, num_conccurent_reqs, &ordering)
                .await
                .map_err(|e| error!("resolving DoT server failed: {}", e))
                .unwrap_or_default();

        let mut using_dot = false;
        if !dot_ips.is_empty() {
            let ns_group_cfg =
                NameServerConfigGroup::from_ips_tls(&dot_ips, 853, dot_provider.to_string(), true);

            let mut root_store = RootCertStore::empty();
            root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
                OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            }));

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
            using_dot = true;

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

        let async_dns_resolver: DynAsyncDNSResolver;
        let resolver_type;
        if resolver_cfg.is_some() {
            async_dns_resolver = Box::new(AsyncResolver::tokio(
                resolver_cfg.unwrap(),
                Self::create_resolver_conf(num_conccurent_reqs, &ordering),
            ));
            resolver_type = if using_dot {
                DNSResolverType::DoT
            } else {
                DNSResolverType::UserProvided
            };
        } else {
            async_dns_resolver =
                Self::create_simple_async_resolver(&vec![], num_conccurent_reqs, ordering.clone());
            resolver_type = DNSResolverType::System;
        }

        Ok(DNSResolver::new(async_dns_resolver, resolver_type))
    }

    async fn resolve_dot_server(
        dot_provider: &str,
        dns_names: &[String],
        num_conccurent_reqs: usize,
        ordering: &DNSQueryOrdering,
    ) -> Result<Vec<IpAddr>, ResolveError> {
        if !dot_provider.is_empty() {
            info!("resovling DoT server: {}", dot_provider);
            // if DoT (DNS over TLS) is specified, a simple resolver is created to resolve the DoT domain first
            let tmp_resolver = Self::create_simple_async_resolver(
                dns_names.as_ref(),
                num_conccurent_reqs,
                ordering.clone(),
            );

            let dot_ips = tmp_resolver
                .lookup(dot_provider)
                .await
                .map_err(|e| {
                    let msg = format!(
                        "failed to resolve DoT domain: {}, error: {}",
                        dot_provider, e
                    );
                    error!("{}", msg);
                    ResolveErrorKind::Msg(msg)
                })
                .into_iter()
                .flatten()
                .collect();

            Ok(dot_ips)
        } else {
            info!("no DoT server is specified");
            Ok(vec![])
        }
    }

    fn create_simple_async_resolver(
        dns_names: &[String],
        num_conccurent_reqs: usize,
        ordering: DNSQueryOrdering,
    ) -> DynAsyncDNSResolver {
        let mut resolver_cfg = ResolverConfig::new();
        let valid_domain_count = Self::add_dns_servers(&mut resolver_cfg, dns_names);
        if valid_domain_count > 0 {
            Box::new(AsyncResolver::tokio(
                resolver_cfg.clone(),
                Self::create_resolver_conf(num_conccurent_reqs, &ordering),
            ))
        } else {
            Self::create_system_resolver(num_conccurent_reqs, ordering)
        }
    }

    fn create_system_resolver(
        num_conccurent_reqs: usize,
        ordering: DNSQueryOrdering,
    ) -> DynAsyncDNSResolver {
        if let Ok((resolver_cfg, resolver_opt)) =
            Self::create_resolver_system_conf(num_conccurent_reqs, &ordering)
        {
            Box::new(AsyncResolver::tokio(resolver_cfg, resolver_opt))
        } else {
            info!("use simple tokio resolver");
            Box::new(SimpleTokioResolver)
        }
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
                let resolver = resolver2(
                    "dns.alidns.com",
                    //"",
                    //vec!["223.5.5.5".to_string()],
                    vec![],
                    2,
                    DNSQueryOrdering::QueryStatistics,
                )
                .await;

                resolver.lookup("google.com").await.unwrap();
            });
    }
}
