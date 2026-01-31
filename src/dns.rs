use anyhow::{Context, Result};
use async_trait::async_trait;
use hickory_resolver::config::{
    LookupIpStrategy, NameServerConfig, NameServerConfigGroup, ResolverConfig, ResolverOpts,
    ServerOrderingStrategy,
};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::xfer::Protocol;
use hickory_resolver::TokioResolver;
use hickory_resolver::{ResolveError, ResolveErrorKind};
use log::{debug, error, info, warn};
use rustls::ClientConfig;
use rustls_platform_verifier::BuilderVerifierExt;
use std::net::IpAddr;
use std::time::Duration;

#[derive(PartialEq, Clone, Copy, Default)]
pub enum DNSQueryOrdering {
    #[default]
    QueryStatistics,
    UserProvidedOrder,
}

#[derive(PartialEq, Clone, Copy)]
pub enum DNSResolverType {
    DoT,
    UserProvided,
    System,
}

#[derive(Clone, Copy, Default)]
pub enum DNSResolverLookupIpStrategy {
    Ipv4Only,
    Ipv6Only,
    Ipv4AndIpv6,
    Ipv6thenIpv4,
    #[default]
    Ipv4thenIpv6,
}

impl DNSResolverLookupIpStrategy {
    fn mapped_type(&self) -> LookupIpStrategy {
        match self {
            DNSResolverLookupIpStrategy::Ipv4Only => LookupIpStrategy::Ipv4Only,
            DNSResolverLookupIpStrategy::Ipv6Only => LookupIpStrategy::Ipv6Only,
            DNSResolverLookupIpStrategy::Ipv4AndIpv6 => LookupIpStrategy::Ipv4AndIpv6,
            DNSResolverLookupIpStrategy::Ipv6thenIpv4 => LookupIpStrategy::Ipv6thenIpv4,
            DNSResolverLookupIpStrategy::Ipv4thenIpv6 => LookupIpStrategy::Ipv4thenIpv6,
        }
    }
}

#[derive(Clone)]
pub struct DNSResolverConfig {
    pub strategy: DNSResolverLookupIpStrategy,
    pub ordering: DNSQueryOrdering,
    pub num_conccurent_reqs: usize,
}

impl Default for DNSResolverConfig {
    fn default() -> Self {
        Self {
            strategy: DNSResolverLookupIpStrategy::default(),
            ordering: DNSQueryOrdering::default(),
            num_conccurent_reqs: 3,
        }
    }
}

impl std::fmt::Display for DNSResolverType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::DoT => "DoT",
            Self::UserProvided => "UserProvided",
            Self::System => "System",
        };
        f.write_str(value)
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
        self.resolver_type
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
        let domain = match domain_with_port.is_some() {
            true => domain_with_port.as_ref().unwrap().as_str(),
            false => domain,
        };
        let ips = tokio::net::lookup_host(domain)
            .await
            .context(format!("failed to resolve domain: {domain}"))?
            .map(|e| e.ip())
            .collect();
        debug!("resolved [{domain}] to {ips:?}");
        Ok(ips)
    }

    async fn lookup_first(&self, domain: &str) -> Result<IpAddr> {
        let domain_with_port = ensure_port(domain);
        let domain = match domain_with_port.is_some() {
            true => domain_with_port.as_ref().unwrap().as_str(),
            false => domain,
        };
        let ip = tokio::net::lookup_host(domain)
            .await
            .context(format!("failed to resolve domain: {domain}"))?
            .next()
            .map(|e| e.ip())
            .context(format!(
                "failed to obtain first resolved ip for domain: {domain}"
            ))?;
        debug!("resolved [{domain}] to {ip:?}");
        Ok(ip)
    }
}

#[async_trait]
impl AsyncDNSResolver for TokioResolver {
    async fn lookup(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let response = self.lookup_ip(domain).await.map_err(|e| {
            error!("failed to resolve domain: {domain}, error: {e}");
            e
        })?;
        let ips = response.iter().collect();
        debug!("resolved [{domain}] to {ips:?}");
        Ok(ips)
    }

    async fn lookup_first(&self, domain: &str) -> Result<IpAddr> {
        let response = self.lookup_ip(domain).await?;
        let ip = response
            .iter()
            .next()
            .context(format!("failed to resolve domain: {domain}"));
        debug!("resolved [{domain}] to {ip:?}");
        ip
    }
}

pub async fn resolver(dot_provider: &str, name_servers: Vec<String>) -> DNSResolver {
    resolver2(dot_provider, name_servers, DNSResolverConfig::default()).await
}

pub async fn resolver2(
    dot_provider: &str,
    name_servers: Vec<String>,
    config: DNSResolverConfig,
) -> DNSResolver {
    if let Ok(resolver) =
        DNSResolverHelper::create_async_resolver(dot_provider, name_servers, config.clone()).await
    {
        resolver
    } else {
        info!("fall back to use system resolver!");
        system_resolver(config)
    }
}

pub fn system_resolver(config: DNSResolverConfig) -> DNSResolver {
    DNSResolver::new(
        DNSResolverHelper::create_system_resolver(config),
        DNSResolverType::System,
    )
}

struct DNSResolverHelper;
impl DNSResolverHelper {
    async fn create_async_resolver(
        dot_provider: &str,
        name_servers: Vec<String>,
        config: DNSResolverConfig,
    ) -> Result<DNSResolver, ResolveError> {
        let mut resolver_cfg = None;
        let mut resolver_tls_config = None;
        let dot_ips: Vec<IpAddr> =
            Self::resolve_dot_server(dot_provider, &name_servers, config.clone())
                .await
                .map_err(|e| error!("resolving DoT server failed: {e}"))
                .unwrap_or_default();

        let mut using_dot = false;
        if !dot_ips.is_empty() {
            if let Some(tls_config) = Self::build_tls_config() {
                let ns_group_cfg = NameServerConfigGroup::from_ips_tls(
                    &dot_ips,
                    853,
                    dot_provider.to_string(),
                    true,
                );
                let dot_resolver_cfg = ResolverConfig::from_parts(None, vec![], ns_group_cfg);
                resolver_cfg = Some(dot_resolver_cfg);
                resolver_tls_config = Some(tls_config);
                using_dot = true;

                info!("will use DoT server: {dot_provider:?} -> {dot_ips:?}");
            } else {
                warn!("failed to build TLS config; DoT disabled");
            }
        }

        // only when failing to use DoT server will normal name servers be used
        if resolver_cfg.is_none() {
            let mut normal_resolver_cfg = ResolverConfig::default();
            let count = Self::add_dns_servers(&mut normal_resolver_cfg, &name_servers);
            if count > 0 {
                resolver_cfg = Some(normal_resolver_cfg);
                info!("will use {count} configured name servers: {name_servers:?}");
            }
        }

        let async_dns_resolver: DynAsyncDNSResolver;
        let resolver_type;
        if let Some(resolver_cfg) = resolver_cfg {
            async_dns_resolver = Box::new(Self::build_resolver_with_config(
                resolver_cfg,
                config,
                resolver_tls_config,
            ));
            resolver_type = if using_dot {
                DNSResolverType::DoT
            } else {
                DNSResolverType::UserProvided
            };
        } else {
            async_dns_resolver = Self::create_simple_async_resolver(&[], config);
            resolver_type = DNSResolverType::System;
        }

        Ok(DNSResolver::new(async_dns_resolver, resolver_type))
    }

    async fn resolve_dot_server(
        dot_provider: &str,
        name_servers: &[String],
        config: DNSResolverConfig,
    ) -> Result<Vec<IpAddr>, ResolveError> {
        if !dot_provider.is_empty() {
            info!("resolving DoT server: {dot_provider}");
            // if DoT (DNS over TLS) is specified, a simple resolver is created to resolve the DoT domain first
            let tmp_resolver = Self::create_simple_async_resolver(name_servers, config);

            let dot_ips = tmp_resolver
                .lookup(dot_provider)
                .await
                .map_err(|e| {
                    let msg = format!("failed to resolve DoT domain: {dot_provider}, error: {e}");
                    error!("{msg}");
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
        name_servers: &[String],
        config: DNSResolverConfig,
    ) -> DynAsyncDNSResolver {
        let mut resolver_cfg = ResolverConfig::new();
        let valid_domain_count = Self::add_dns_servers(&mut resolver_cfg, name_servers);
        if valid_domain_count > 0 {
            Box::new(Self::build_resolver_with_config(resolver_cfg, config, None))
        } else {
            Self::create_system_resolver(config)
        }
    }

    fn create_system_resolver(config: DNSResolverConfig) -> DynAsyncDNSResolver {
        match TokioResolver::builder_tokio() {
            Ok(mut builder) => {
                Self::apply_resolver_opts(builder.options_mut(), &config);
                Box::new(builder.build())
            }
            Err(_) => {
                info!("use simple tokio resolver");
                Box::new(SimpleTokioResolver)
            }
        }
    }

    fn add_dns_servers(resolver_cfg: &mut ResolverConfig, name_servers: &[String]) -> usize {
        let mut valid_domain_count = 0;
        for domain in name_servers.iter() {
            if let Ok(ip) = format!("{}:53", domain).parse() {
                resolver_cfg.add_name_server(NameServerConfig::new(ip, Protocol::Udp));
                resolver_cfg.add_name_server(NameServerConfig::new(ip, Protocol::Tcp));
                valid_domain_count += 1;
                info!("added dns server: {ip}");
            }
        }
        valid_domain_count
    }

    fn build_resolver_with_config(
        resolver_cfg: ResolverConfig,
        config: DNSResolverConfig,
        tls_config: Option<ClientConfig>,
    ) -> TokioResolver {
        let mut builder =
            TokioResolver::builder_with_config(resolver_cfg, TokioConnectionProvider::default());
        Self::apply_resolver_opts(builder.options_mut(), &config);
        if let Some(tls_config) = tls_config {
            builder.options_mut().tls_config = tls_config;
        }
        builder.build()
    }

    fn apply_resolver_opts(opts: &mut ResolverOpts, config: &DNSResolverConfig) {
        opts.timeout = Duration::from_secs(3);
        opts.ip_strategy = config.strategy.mapped_type();
        opts.attempts = 2;
        opts.num_concurrent_reqs = config.num_conccurent_reqs;
        opts.server_ordering_strategy = if config.ordering == DNSQueryOrdering::UserProvidedOrder {
            ServerOrderingStrategy::UserProvidedOrder
        } else {
            ServerOrderingStrategy::QueryStatistics
        };
    }

    fn build_tls_config() -> Option<ClientConfig> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        ClientConfig::builder()
            .with_platform_verifier()
            .map(|builder| builder.with_no_client_auth())
            .map_err(|err| {
                error!("failed to build platform TLS verifier: {err}");
            })
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_dns() {
        let config = DNSResolverConfig {
            strategy: DNSResolverLookupIpStrategy::Ipv6thenIpv4,
            num_conccurent_reqs: 2,
            ordering: DNSQueryOrdering::QueryStatistics,
        };

        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let resolver =
                    resolver2("dns.alidns.com", vec!["223.5.5.5".to_string()], config).await;

                resolver.lookup("github.com").await.unwrap();
            });
    }
}
