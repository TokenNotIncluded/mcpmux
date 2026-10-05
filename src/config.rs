use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub public_url: String,
    #[serde(default = "listen")]
    pub listen: String,
    #[serde(default)]
    pub origins: Vec<String>,
    #[serde(default = "max_sessions")]
    pub max_sessions: usize,
    #[serde(default = "idle")]
    pub session_idle_seconds: u64,
    #[serde(default)]
    pub upstreams: BTreeMap<String, Upstream>,
    #[serde(default)]
    pub routes: BTreeMap<String, Route>,
    #[serde(default)]
    pub users: BTreeMap<String, User>,
    #[serde(default)]
    pub clients: BTreeMap<String, Client>,
    #[serde(default)]
    pub tokens: BTreeMap<String, ServiceToken>,
}
fn listen() -> String {
    "127.0.0.1:8088".into()
}
fn max_sessions() -> usize {
    32
}
fn idle() -> u64 {
    600
}
fn scopes() -> Vec<String> {
    vec!["mcp:access".into()]
}
#[derive(Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum Upstream {
    Http {
        url: String,
        bearer_file: Option<String>,
    },
    Stdio {
        command: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        env: BTreeMap<String, String>,
        #[serde(default)]
        env_file: Option<String>,
    },
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub upstream: Option<String>,
    pub alias: Option<String>,
    pub path: Option<String>,
    #[serde(default = "scopes")]
    pub scopes: Vec<String>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub password_sha256: String,
    pub routes: Vec<String>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Client {
    pub redirect_uris: Vec<String>,
    pub routes: Vec<String>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceToken {
    pub sha256: String,
    pub subject: String,
    pub route: String,
    #[serde(default = "scopes")]
    pub scopes: Vec<String>,
}
impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let c: Self = toml::from_str(&std::fs::read_to_string(path)?).context("invalid TOML")?;
        c.validate()?;
        Ok(c)
    }
    pub fn path(&self, name: &str) -> String {
        self.routes[name]
            .path
            .clone()
            .unwrap_or_else(|| format!("/mcp/{name}"))
    }
    pub fn resolve(&self, name: &str) -> Result<&Upstream> {
        let mut name = name;
        let mut seen = BTreeSet::new();
        loop {
            if !seen.insert(name) {
                bail!("alias cycle at {name}");
            }
            let r = self.routes.get(name).context("unknown route")?;
            match (&r.upstream, &r.alias) {
                (Some(u), None) => return self.upstreams.get(u).context("unknown upstream"),
                (None, Some(a)) => name = a,
                _ => bail!("route must have exactly one of upstream or alias"),
            }
        }
    }
    fn validate(&self) -> Result<()> {
        let u = url::Url::parse(&self.public_url)?;
        if u.scheme() != "https"
            || u.path() != "/"
            || u.query().is_some()
            || u.fragment().is_some()
            || !u.username().is_empty()
        {
            bail!("public_url must be an HTTPS origin without a path");
        }
        if self.public_url.ends_with('/') {
            bail!("public_url must omit trailing slash");
        }
        let addr: std::net::SocketAddr = self.listen.parse()?;
        if !addr.ip().is_loopback() {
            bail!("listen must be loopback; terminate TLS at a reverse proxy");
        }
        if self.max_sessions == 0 || self.max_sessions > 1024 || self.session_idle_seconds == 0 {
            bail!("invalid session limits");
        }
        let mut paths = BTreeSet::new();
        for (name, r) in &self.routes {
            let path = self.path(name);
            if !path.starts_with('/')
                || path.ends_with('/')
                || path.contains("//")
                || !path
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/_-".contains(&b))
                || ["/authorize", "/token", "/healthz"].contains(&path.as_str())
                || !paths.insert(path)
            {
                bail!("invalid, reserved or duplicate route path");
            }

            if name.is_empty()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                bail!("invalid route name {name}");
            }
            self.resolve(name)?;
            if r.scopes.is_empty()
                || r.scopes.iter().any(|s| {
                    s.is_empty()
                        || !s
                            .bytes()
                            .all(|b| (0x21..=0x7e).contains(&b) && b != b'"' && b != b'\\')
                })
            {
                bail!("invalid scopes");
            }
        }
        for upstream in self.upstreams.values() {
            match upstream {
                Upstream::Http { url, .. } => {
                    let u = url::Url::parse(url)?;
                    if !u.username().is_empty()
                        || u.password().is_some()
                        || u.query().is_some()
                        || u.fragment().is_some()
                        || (u.scheme() != "https"
                            && !(u.scheme() == "http"
                                && matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "::1"))))
                    {
                        bail!(
                            "upstream must be HTTPS or loopback HTTP, without URL credentials/query/fragment"
                        );
                    }
                }
                Upstream::Stdio { command, .. } => {
                    if !command.starts_with('/') {
                        bail!("stdio command must be an absolute path");
                    }
                }
            }
        }
        for user in self.users.values() {
            check_hash(&user.password_sha256)?;
            self.check_routes(&user.routes)?;
        }
        for client in self.clients.values() {
            self.check_routes(&client.routes)?;
            for redirect in &client.redirect_uris {
                let u = url::Url::parse(redirect)?;
                if u.fragment().is_some()
                    || !u.username().is_empty()
                    || !(u.scheme() == "https"
                        || (u.scheme() == "http"
                            && matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "::1"))))
                {
                    bail!("redirect must be HTTPS or loopback HTTP");
                }
            }
        }
        for t in self.tokens.values() {
            check_hash(&t.sha256)?;
            self.check_routes(std::slice::from_ref(&t.route))?;
        }
        Ok(())
    }
    fn check_routes(&self, names: &[String]) -> Result<()> {
        for n in names {
            if !self.routes.contains_key(n) {
                bail!("unknown permitted route {n}");
            }
        }
        Ok(())
    }
}
fn check_hash(s: &str) -> Result<()> {
    if s.len() != 64 || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
        bail!("expected SHA-256 hex of a high-entropy generated secret");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn aliases_and_cycles() {
        let mut c: Config=toml::from_str("public_url='https://example.com'\n[upstreams.local]\ntype='http'\nurl='http://127.0.0.1:9999/mcp'\n[routes.a]\nupstream='local'\n[routes.b]\nalias='a'").unwrap();
        assert!(c.validate().is_ok());
        c.routes.get_mut("a").unwrap().upstream = None;
        c.routes.get_mut("a").unwrap().alias = Some("b".into());
        assert!(c.validate().is_err());
    }
}
