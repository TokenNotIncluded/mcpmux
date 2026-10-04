use crate::{App, reply};
use axum::{
    extract::{Form, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;

pub fn secret() -> String {
    let mut b = [0u8; 32];
    rand::rng().fill_bytes(&mut b);
    URL_SAFE_NO_PAD.encode(b)
}
pub fn hash(s: &str) -> String {
    format!("{:x}", Sha256::digest(s.as_bytes()))
}
fn eq(a: &str, b: &str) -> bool {
    bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}
#[derive(Clone)]
pub struct Principal {
    pub subject: String,
    pub client: String,
}
#[derive(Clone)]
pub struct Grant {
    pub principal: Principal,
    pub route: String,
    pub scopes: Vec<String>,
    pub expires: Instant,
}
#[derive(Clone, Deserialize)]
pub struct Authorization {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    resource: String,
    code_challenge: String,
    code_challenge_method: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    scope: String,
}
#[derive(Clone)]
pub struct Pending {
    request: Authorization,
    route: String,
    scopes: Vec<String>,
    expires: Instant,
}
pub struct Code {
    pending: Pending,
    principal: Principal,
}
#[derive(Default)]
pub struct Store {
    pending: HashMap<String, Pending>,
    codes: HashMap<String, Code>,
    tokens: HashMap<String, Grant>,
    failures: Vec<Instant>,
}
impl Store {
    pub fn prune(&mut self) {
        let now = Instant::now();
        self.pending.retain(|_, v| v.expires > now);
        self.codes.retain(|_, v| v.pending.expires > now);
        self.tokens.retain(|_, v| v.expires > now);
        self.failures
            .retain(|t| now.duration_since(*t) < Duration::from_secs(60));
    }
}
fn resource_route(app: &App, resource: &str) -> Option<String> {
    let prefix = format!("{}/mcp/", app.config.public_url);
    let r = resource.strip_prefix(&prefix)?;
    app.config.routes.contains_key(r).then(|| r.into())
}
pub async fn metadata(State(app): State<Arc<App>>) -> Response {
    let base = &app.config.public_url;
    reply(
        StatusCode::OK,
        json!({"issuer":base,"authorization_endpoint":format!("{base}/authorize"),"token_endpoint":format!("{base}/token"),"response_types_supported":["code"],"grant_types_supported":["authorization_code"],"code_challenge_methods_supported":["S256"],"token_endpoint_auth_methods_supported":["none"],"authorization_response_iss_parameter_supported":true,"scopes_supported":app.config.routes.values().flat_map(|r|r.scopes.clone()).collect::<std::collections::BTreeSet<_>>()}),
    )
}
fn error(e: &str) -> Response {
    reply(StatusCode::BAD_REQUEST, json!({"error":e}))
}
pub async fn authorize(State(app): State<Arc<App>>, Query(q): Query<Authorization>) -> Response {
    let Some(client) = app.config.clients.get(&q.client_id) else {
        return error("invalid_client");
    };
    if !client.redirect_uris.contains(&q.redirect_uri) {
        return error("invalid_redirect_uri");
    }
    let Some(route) = resource_route(&app, &q.resource) else {
        return error("invalid_target");
    };
    let scopes: Vec<String> = if q.scope.is_empty() {
        app.config.routes[&route].scopes.clone()
    } else {
        q.scope.split_whitespace().map(String::from).collect()
    };
    if q.response_type != "code"
        || q.code_challenge_method != "S256"
        || URL_SAFE_NO_PAD
            .decode(&q.code_challenge)
            .map(|v| v.len())
            .ok()
            != Some(32)
    {
        return error("invalid_request");
    }
    if !client.routes.contains(&route)
        || scopes
            .iter()
            .any(|s| !app.config.routes[&route].scopes.contains(s))
    {
        return error("invalid_scope");
    }
    let mut store = app.auth.lock().await;
    store.prune();
    if store.pending.len() + store.codes.len() >= 1024 {
        return reply(
            StatusCode::TOO_MANY_REQUESTS,
            json!({"error":"temporarily_unavailable"}),
        );
    }
    let txn = secret();
    let page = format!(
        "<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width'><title>mcpmux authorization</title><style>body{{font:16px system-ui;max-width:32rem;margin:10vh auto;padding:1rem}}input,button{{display:block;margin:1rem 0;padding:.7rem}}</style><h1>Authorize mcpmux</h1><p>Client: <strong>{}</strong></p><p>Resource: {}</p><p>Permissions: {}</p><form method=post action=/authorize><input type=hidden name=transaction value='{}'><label>User<input name=username autocomplete=username required></label><label>Access password<input name=password type=password autocomplete=current-password required></label><button>Approve access</button></form></html>",
        escape(&q.client_id),
        escape(&q.resource),
        escape(&scopes.join(" ")),
        txn
    );
    store.pending.insert(
        hash(&txn),
        Pending {
            request: q,
            route,
            scopes,
            expires: Instant::now() + Duration::from_secs(600),
        },
    );
    let mut response = Html(page).into_response();
    response.headers_mut().insert("content-security-policy","default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'".parse().unwrap());
    response
}
fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
#[derive(Deserialize)]
pub struct Approval {
    transaction: String,
    username: String,
    password: String,
}
pub async fn approve(
    State(app): State<Arc<App>>,
    form: Result<Form<Approval>, axum::extract::rejection::FormRejection>,
) -> Response {
    let Ok(Form(f)) = form else {
        return error("invalid_request");
    };
    let mut store = app.auth.lock().await;
    store.prune();
    if store.failures.len() >= 20 {
        return reply(StatusCode::TOO_MANY_REQUESTS, json!({"error":"slow_down"}));
    }
    let Some(pending) = store.pending.remove(&hash(&f.transaction)) else {
        return error("invalid_request");
    };
    let valid = app.config.users.get(&f.username).is_some_and(|u| {
        eq(&u.password_sha256, &hash(&f.password)) && u.routes.contains(&pending.route)
    });
    if !valid {
        store.failures.push(Instant::now());
        return reply(StatusCode::FORBIDDEN, json!({"error":"access_denied"}));
    }
    let code = secret();
    let mut redirect = url::Url::parse(&pending.request.redirect_uri).unwrap();
    redirect
        .query_pairs_mut()
        .append_pair("code", &code)
        .append_pair("state", &pending.request.state)
        .append_pair("iss", &app.config.public_url);
    let principal = Principal {
        subject: f.username,
        client: pending.request.client_id.clone(),
    };
    let mut pending = pending;
    pending.expires = Instant::now() + Duration::from_secs(60);
    store.codes.insert(hash(&code), Code { pending, principal });
    let mut response = StatusCode::SEE_OTHER.into_response();
    response
        .headers_mut()
        .insert("location", redirect.as_str().parse().unwrap());
    response
}
#[derive(Deserialize)]
pub struct Exchange {
    grant_type: String,
    code: String,
    client_id: String,
    redirect_uri: String,
    resource: String,
    code_verifier: String,
}
pub async fn token(
    State(app): State<Arc<App>>,
    form: Result<Form<Exchange>, axum::extract::rejection::FormRejection>,
) -> Response {
    let Ok(Form(f)) = form else {
        return error("invalid_request");
    };
    if f.grant_type != "authorization_code" {
        return error("unsupported_grant_type");
    }
    if !(43..=128).contains(&f.code_verifier.len())
        || !f
            .code_verifier
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-._~".contains(&c))
    {
        return error("invalid_grant");
    }
    let mut store = app.auth.lock().await;
    store.prune();
    let Some(code) = store.codes.remove(&hash(&f.code)) else {
        return error("invalid_grant");
    };
    let q = &code.pending.request;
    if q.client_id != f.client_id
        || q.redirect_uri != f.redirect_uri
        || q.resource != f.resource
        || !eq(
            &q.code_challenge,
            &URL_SAFE_NO_PAD.encode(Sha256::digest(f.code_verifier.as_bytes())),
        )
    {
        return error("invalid_grant");
    }
    if store.tokens.len() >= 4096 {
        return error("temporarily_unavailable");
    }
    let token = secret();
    let scope = code.pending.scopes.join(" ");
    store.tokens.insert(
        hash(&token),
        Grant {
            principal: code.principal,
            route: code.pending.route,
            scopes: code.pending.scopes,
            expires: Instant::now() + Duration::from_secs(3600),
        },
    );
    reply(
        StatusCode::OK,
        json!({"access_token":token,"token_type":"Bearer","expires_in":3600,"scope":scope}),
    )
}
pub async fn authenticate(
    app: &App,
    route: &str,
    headers: &HeaderMap,
) -> Result<Principal, Box<Response>> {
    let challenge = |status: StatusCode, error: Option<&str>| {
        let mut r = reply(status, json!({"error":error.unwrap_or("unauthorized")}));
        let mut value = format!(
            "Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource/mcp/{}\", scope=\"{}\"",
            app.config.public_url,
            route,
            app.config.routes[route].scopes.join(" ")
        );
        if let Some(e) = error {
            value.push_str(&format!(", error=\"{e}\""));
        }
        r.headers_mut()
            .insert("www-authenticate", value.parse().unwrap());
        Box::new(r)
    };
    if headers.get_all("authorization").iter().count() != 1 {
        return Err(challenge(StatusCode::UNAUTHORIZED, None));
    }
    let raw = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split_once(' '))
        .filter(|(s, _)| s.eq_ignore_ascii_case("bearer"))
        .map(|(_, t)| t);
    let Some(raw) = raw.filter(|t| !t.is_empty() && !t.contains(char::is_whitespace)) else {
        return Err(challenge(StatusCode::UNAUTHORIZED, Some("invalid_token")));
    };
    let hashed = hash(raw);
    let grant = {
        let mut store = app.auth.lock().await;
        store.prune();
        store.tokens.get(&hashed).cloned()
    };
    let grant = grant.or_else(|| {
        app.config
            .tokens
            .iter()
            .find(|(_, t)| eq(&t.sha256, &hashed))
            .map(|(name, t)| Grant {
                principal: Principal {
                    subject: t.subject.clone(),
                    client: format!("service:{name}"),
                },
                route: t.route.clone(),
                scopes: t.scopes.clone(),
                expires: Instant::now() + Duration::from_secs(1),
            })
    });
    let Some(g) = grant.filter(|g| g.route == route) else {
        return Err(challenge(StatusCode::UNAUTHORIZED, Some("invalid_token")));
    };
    if !app.config.routes[route]
        .scopes
        .iter()
        .all(|s| g.scopes.contains(s))
    {
        return Err(challenge(StatusCode::FORBIDDEN, Some("insufficient_scope")));
    }
    Ok(g.principal)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn secrets_are_strong() {
        let s = secret();
        assert_eq!(s.len(), 43);
        assert_ne!(s, secret());
        assert_eq!(hash(&s).len(), 64);
    }
}
