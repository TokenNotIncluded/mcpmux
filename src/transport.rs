use crate::{
    App,
    auth::{Principal, secret},
    config::Upstream,
    reply,
};
use axum::{
    body::{Body, Bytes},
    http::{HeaderMap, Method, StatusCode},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
};
use futures_util::StreamExt;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    convert::Infallible,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::AsyncWriteExt,
    process::{Child, ChildStdin, Command},
    sync::{Mutex as AsyncMutex, broadcast, mpsc},
};
use tokio_util::codec::{FramedRead, LinesCodec};

const MAX_LINE: usize = 1024 * 1024;
pub struct Stdio {
    input: AsyncMutex<ChildStdin>,
    pending: Arc<Mutex<HashMap<String, mpsc::Sender<Value>>>>,
    events: broadcast::Sender<Option<Value>>,
    child: Mutex<Child>,
    reader: tokio::task::JoinHandle<()>,
}
impl Drop for Stdio {
    fn drop(&mut self) {
        self.reader.abort();
        if let Ok(c) = self.child.get_mut() {
            let _ = c.start_kill();
        }
    }
}
impl Stdio {
    async fn start(upstream: &Upstream) -> anyhow::Result<Arc<Self>> {
        let Upstream::Stdio {
            command,
            args,
            env,
            env_file,
        } = upstream
        else {
            unreachable!()
        };
        let mut cmd = Command::new(command);
        cmd.args(args)
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("HOME", "/var/lib/mcpmux")
            .envs(env)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true);
        if let Some(file) = env_file {
            let vars: HashMap<String, String> = toml::from_str(&std::fs::read_to_string(file)?)?;
            cmd.envs(vars);
        }
        let mut child = cmd.spawn()?;
        let input = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let pending: Arc<Mutex<HashMap<String, mpsc::Sender<Value>>>> = Arc::default();
        let (events, _) = broadcast::channel(16);
        let p = pending.clone();
        let e = events.clone();
        let reader = tokio::spawn(async move {
            let mut lines = FramedRead::new(stdout, LinesCodec::new_with_max_length(MAX_LINE));
            while let Some(Ok(line)) = lines.next().await {
                let Ok(v) = serde_json::from_str::<Value>(&line) else {
                    break;
                };
                if v.get("method").is_none() && v.get("id").is_some() {
                    let tx = p.lock().unwrap().remove(&v["id"].to_string());
                    if let Some(tx) = tx
                        && tx.try_send(v).is_err()
                    {
                        break;
                    }
                } else {
                    let _ = e.send(Some(v.clone()));
                    // Legacy request-scoped notifications; modern processes have one request.
                    if v.get("id").is_none() || v.get("method").is_some() {
                        let senders: Vec<_> = p.lock().unwrap().values().cloned().collect();
                        for tx in senders {
                            if tx.try_send(v.clone()).is_err() {
                                return;
                            }
                        }
                    }
                }
            }
            p.lock().unwrap().clear();
        });
        Ok(Arc::new(Self {
            input: AsyncMutex::new(input),
            pending,
            events,
            child: Mutex::new(child),
            reader,
        }))
    }
    pub fn terminate(&self) {
        self.reader.abort();
        let _ = self.child.lock().unwrap().start_kill();
        self.pending.lock().unwrap().clear();
        let _ = self.events.send(None);
    }
    async fn send(&self, value: &Value) -> anyhow::Result<()> {
        let mut bytes = serde_json::to_vec(value)?;
        bytes.push(b'\n');
        let mut input = self.input.lock().await;
        input.write_all(&bytes).await?;
        input.flush().await?;
        Ok(())
    }
}
#[derive(Clone)]
pub enum Backend {
    Stdio(Arc<Stdio>),
    Http(String),
}
pub struct Session {
    pub route: String,
    pub principal: Principal,
    pub backend: Backend,
    pub touched: Instant,
}
impl Session {
    fn matches(&self, route: &str, p: &Principal) -> bool {
        self.route == route
            && self.principal.subject == p.subject
            && self.principal.client == p.client
    }
}
fn err(status: StatusCode, e: &str) -> Response {
    reply(status, json!({"error":e}))
}
fn allowed_header(name: &str) -> bool {
    matches!(name, "accept" | "content-type" | "last-event-id") || name.starts_with("mcp-")
}
fn hop_headers(headers: &HeaderMap) -> Vec<String> {
    let mut out = vec![
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ]
    .into_iter()
    .map(String::from)
    .collect::<Vec<_>>();
    for v in headers.get_all("connection") {
        if let Ok(v) = v.to_str() {
            out.extend(v.split(',').map(|s| s.trim().to_ascii_lowercase()));
        }
    }
    out
}
pub async fn forward(
    app: Arc<App>,
    route: String,
    p: Principal,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok(permit) = app.active.clone().try_acquire_owned() else {
        return err(StatusCode::SERVICE_UNAVAILABLE, "too many active requests");
    };
    let upstream = app.config.resolve(&route).unwrap();
    if let Upstream::Stdio { .. } = upstream
        && let Some(version) = headers
            .get("mcp-protocol-version")
            .and_then(|v| v.to_str().ok())
        && !["2025-03-26", "2025-06-18", "2025-11-25", "2026-07-28"].contains(&version)
    {
        let value: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        return reply(
            StatusCode::BAD_REQUEST,
            json!({"jsonrpc":"2.0","id":value.get("id"),"error":{"code":-32022,"message":"Unsupported protocol version","data":{"supported":["2026-07-28","2025-11-25","2025-06-18","2025-03-26"],"requested":version}}}),
        );
    }
    let modern = headers
        .get("mcp-protocol-version")
        .is_some_and(|v| v == "2026-07-28");
    let sid = if modern {
        None
    } else {
        headers
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .map(String::from)
    };
    let backend = if let Some(sid) = &sid {
        let mut sessions = app.sessions.lock().await;
        let Some(s) = sessions.get_mut(sid).filter(|s| s.matches(&route, &p)) else {
            return err(StatusCode::NOT_FOUND, "unknown session");
        };
        s.touched = Instant::now();
        Some(s.backend.clone())
    } else {
        None
    };
    match upstream {
        Upstream::Http { url, bearer_file } => {
            let mut request = app.http.request(method.clone(), url);
            let hop = hop_headers(&headers);
            for (name, value) in &headers {
                if allowed_header(name.as_str())
                    && name != "mcp-session-id"
                    && !hop.contains(&name.as_str().to_string())
                {
                    request = request.header(name, value);
                }
            }
            if let Some(Backend::Http(remote)) = backend {
                request = request.header("mcp-session-id", remote);
            }
            if let Some(file) = bearer_file {
                let Ok(token) = std::fs::read_to_string(file) else {
                    return err(StatusCode::BAD_GATEWAY, "upstream credential unavailable");
                };
                request = request.bearer_auth(token.trim());
            }
            let response = match tokio::time::timeout(
                Duration::from_secs(30),
                request.body(body).send(),
            )
            .await
            {
                Ok(Ok(r)) => r,
                _ => return err(StatusCode::BAD_GATEWAY, "upstream connection failed"),
            };
            let status = response.status();
            let mut out = HeaderMap::new();
            let hop = hop_headers(response.headers());
            for (name, value) in response.headers() {
                if !hop.contains(&name.as_str().to_string())
                    && (name == "content-type"
                        || name == "mcp-protocol-version"
                        || name == "cache-control"
                        || name == "retry-after")
                {
                    out.insert(name, value.clone());
                }
            }
            // An upstream 401 must never advertise its OAuth server for our resource.
            if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                return err(
                    StatusCode::BAD_GATEWAY,
                    "upstream credential rejected; configure a separate upstream credential",
                );
            }
            if !modern && status.is_success() {
                if let Some(remote) = response
                    .headers()
                    .get("mcp-session-id")
                    .and_then(|v| v.to_str().ok())
                {
                    let id = sid.clone().unwrap_or_else(secret);
                    let mut sessions = app.sessions.lock().await;
                    if !sessions.contains_key(&id) && sessions.len() >= app.config.max_sessions {
                        return err(StatusCode::SERVICE_UNAVAILABLE, "session limit reached");
                    }
                    sessions.insert(
                        id.clone(),
                        Session {
                            route,
                            principal: p,
                            backend: Backend::Http(remote.into()),
                            touched: Instant::now(),
                        },
                    );
                    out.insert("mcp-session-id", id.parse().unwrap());
                } else if let Some(sid) = &sid {
                    out.insert("mcp-session-id", sid.parse().unwrap());
                }
                if method == Method::DELETE
                    && let Some(sid) = &sid
                {
                    app.sessions.lock().await.remove(sid);
                }
            }
            out.insert("x-accel-buffering", "no".parse().unwrap());
            let stream = async_stream::stream! {let _permit=permit;let mut s=response.bytes_stream();while let Some(item)=s.next().await{yield item;}};
            let mut r = Response::new(Body::from_stream(stream));
            *r.status_mut() = status;
            *r.headers_mut() = out;
            r
        }
        Upstream::Stdio { .. } => {
            if modern && method != Method::POST {
                return err(StatusCode::METHOD_NOT_ALLOWED, "POST required");
            }
            if method == Method::DELETE {
                let Some(id) = sid else {
                    return err(StatusCode::NOT_FOUND, "session required");
                };
                if let Some(Backend::Stdio(s)) = backend {
                    s.terminate();
                }
                app.sessions.lock().await.remove(&id);
                return StatusCode::NO_CONTENT.into_response();
            }
            if method == Method::GET {
                let Some(Backend::Stdio(s)) = backend else {
                    return err(StatusCode::METHOD_NOT_ALLOWED, "session required");
                };
                if headers.contains_key("last-event-id") {
                    return err(
                        StatusCode::BAD_REQUEST,
                        "stdio streams do not support replay",
                    );
                }
                let mut rx = s.events.subscribe();
                let stream = async_stream::stream! {let _permit=permit;let _session=s;while let Ok(Some(v))=rx.recv().await {yield Ok::<_,Infallible>(Event::default().event("message").data(v.to_string()));}};
                return Sse::new(stream)
                    .keep_alive(KeepAlive::default())
                    .into_response();
            }
            if method != Method::POST {
                return err(StatusCode::METHOD_NOT_ALLOWED, "POST required");
            }
            let value: Value = match serde_json::from_slice(&body) {
                Ok(v) => v,
                Err(_) => return err(StatusCode::BAD_REQUEST, "invalid JSON"),
            };
            if value["jsonrpc"] != "2.0" || !value.is_object() {
                return err(StatusCode::BAD_REQUEST, "single JSON-RPC object required");
            }
            if modern && let Some(r) = validate_modern(&headers, &value) {
                return r;
            }
            if let Some(id) = value.get("id")
                && !(id.is_string() || id.is_i64() || id.is_u64())
            {
                return reply(
                    StatusCode::BAD_REQUEST,
                    json!({"jsonrpc":"2.0","error":{"code":-32600,"message":"Invalid request ID"}}),
                );
            }
            let is_init = value["method"] == "initialize";
            let (s, new_sid) = match backend {
                Some(Backend::Stdio(s)) => (s, None),
                _ => {
                    if !modern && !is_init {
                        return err(StatusCode::BAD_REQUEST, "initialize required");
                    }
                    let s = match Stdio::start(upstream).await {
                        Ok(s) => s,
                        Err(_) => {
                            return err(StatusCode::BAD_GATEWAY, "stdio process failed to start");
                        }
                    };
                    if modern {
                        (s, None)
                    } else {
                        let id = secret();
                        let mut sessions = app.sessions.lock().await;
                        if sessions.len() >= app.config.max_sessions {
                            return err(StatusCode::SERVICE_UNAVAILABLE, "session limit reached");
                        }
                        sessions.insert(
                            id.clone(),
                            Session {
                                route,
                                principal: p,
                                backend: Backend::Stdio(s.clone()),
                                touched: Instant::now(),
                            },
                        );
                        (s, Some(id))
                    }
                }
            };
            // Responses to legacy server-initiated requests are forwarded like notifications.
            if value.get("id").is_none() || value.get("method").is_none() {
                return match s.send(&value).await {
                    Ok(_) => StatusCode::ACCEPTED.into_response(),
                    Err(_) => err(StatusCode::BAD_GATEWAY, "stdio closed"),
                };
            }
            let key = value["id"].to_string();
            let (tx, mut rx) = mpsc::channel(16);
            {
                let mut pending = s.pending.lock().unwrap();
                if pending.contains_key(&key) {
                    return err(StatusCode::CONFLICT, "duplicate in-flight request id");
                }
                pending.insert(key.clone(), tx);
            }
            if s.send(&value).await.is_err() {
                s.pending.lock().unwrap().remove(&key);
                return err(StatusCode::BAD_GATEWAY, "stdio closed");
            }
            let first = if modern {
                match tokio::time::timeout(Duration::from_secs(120), rx.recv()).await {
                    Ok(Some(v)) => {
                        if v.get("method").is_none() {
                            let status = match v.pointer("/error/code").and_then(Value::as_i64) {
                                Some(-32601) => StatusCode::NOT_FOUND,
                                Some(-32700 | -32600 | -32602 | -32020 | -32021 | -32022) => {
                                    StatusCode::BAD_REQUEST
                                }
                                _ => StatusCode::OK,
                            };
                            s.pending.lock().unwrap().remove(&key);
                            return reply(status, v);
                        }
                        Some(v)
                    }
                    _ => {
                        s.pending.lock().unwrap().remove(&key);
                        return err(StatusCode::BAD_GATEWAY, "stdio closed or timed out");
                    }
                }
            } else {
                None
            };
            let lifetime = if value["method"] == "subscriptions/listen" {
                86400
            } else {
                120
            };
            struct Cleanup {
                session: Arc<Stdio>,
                key: String,
            }
            impl Drop for Cleanup {
                fn drop(&mut self) {
                    self.session.pending.lock().unwrap().remove(&self.key);
                }
            }
            let cleanup = Cleanup { session: s, key };
            let id = value["id"].clone();
            let stream = async_stream::stream! {
                let _permit=permit;let _cleanup=cleanup;
                if let Some(v)=first {yield Ok::<_,Infallible>(Event::default().event("message").data(v.to_string()));}
                let deadline=tokio::time::Instant::now()+Duration::from_secs(lifetime);
                loop {match tokio::time::timeout_at(deadline,rx.recv()).await {
                    Ok(Some(v))=>{let final_reply=v.get("method").is_none();yield Ok::<_,Infallible>(Event::default().event("message").data(v.to_string()));if final_reply{break}}
                    _=>{yield Ok(Event::default().event("message").data(json!({"jsonrpc":"2.0","id":id,"error":{"code":-32603,"message":"upstream closed or timed out"}}).to_string()));break}
                }}
            };
            let mut response = Sse::new(stream)
                .keep_alive(KeepAlive::default())
                .into_response();
            response
                .headers_mut()
                .insert("x-accel-buffering", "no".parse().unwrap());
            if let Some(id) = new_sid {
                response
                    .headers_mut()
                    .insert("mcp-session-id", id.parse().unwrap());
            }
            response
        }
    }
}
fn validate_modern(h: &HeaderMap, v: &Value) -> Option<Response> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let get = |k: &str| h.get(k).and_then(|s| s.to_str().ok());
    let version = v
        .pointer("/params/_meta/io.modelcontextprotocol~1protocolVersion")
        .and_then(Value::as_str);
    let method = v["method"].as_str();
    let mut mismatch =
        version != get("mcp-protocol-version") || method.is_none() || method != get("mcp-method");
    if matches!(
        method,
        Some("tools/call" | "resources/read" | "prompts/get")
    ) {
        let source = if method == Some("resources/read") {
            v["params"]["uri"].as_str()
        } else {
            v["params"]["name"].as_str()
        };
        let name = get("mcp-name").and_then(|s| {
            if let Some(b) = s
                .strip_prefix("=?base64?")
                .and_then(|s| s.strip_suffix("?="))
            {
                String::from_utf8(STANDARD.decode(b).ok()?).ok()
            } else {
                Some(s.into())
            }
        });
        mismatch |= source.is_none() || source != name.as_deref();
    }
    mismatch.then(||reply(StatusCode::BAD_REQUEST,json!({"jsonrpc":"2.0","id":v.get("id"),"error":{"code":-32020,"message":"HeaderMismatch"}})))
}
