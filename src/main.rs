mod auth;
mod config;
mod transport;
use axum::{
    Router,
    body::to_bytes,
    extract::{DefaultBodyLimit, Path, Request, State},
    http::{Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, get, post},
};
use config::Config;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    path::Path as FilePath,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, Semaphore};

pub struct App {
    config: Config,
    auth: Mutex<auth::Store>,
    sessions: Mutex<HashMap<String, transport::Session>>,
    http: reqwest::Client,
    active: Arc<Semaphore>,
}
pub fn reply(status: StatusCode, value: Value) -> Response {
    (status, axum::Json(value)).into_response()
}
async fn security(req: Request, next: Next) -> Response {
    let mut r = next.run(req).await;
    r.headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    r.headers_mut()
        .insert("x-content-type-options", "nosniff".parse().unwrap());
    r.headers_mut()
        .insert("referrer-policy", "no-referrer".parse().unwrap());
    r
}
async fn resource(State(app): State<Arc<App>>, Path(name): Path<String>) -> Response {
    if app
        .config
        .routes
        .get(&name)
        .is_some_and(|r| r.path.is_some())
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    resource_for(&app, &name)
}
fn resource_for(app: &App, name: &str) -> Response {
    let Some(route) = app.config.routes.get(name) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    reply(
        StatusCode::OK,
        json!({"resource":format!("{}{}",app.config.public_url,app.config.path(name)),"authorization_servers":[app.config.public_url],"scopes_supported":route.scopes,"bearer_methods_supported":["header"]}),
    )
}
async fn gateway(State(app): State<Arc<App>>, Path(name): Path<String>, req: Request) -> Response {
    if app
        .config
        .routes
        .get(&name)
        .is_some_and(|r| r.path.is_some())
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    gateway_for(app, name, req).await
}
async fn gateway_for(app: Arc<App>, name: String, req: Request) -> Response {
    if !app.config.routes.contains_key(&name) {
        return StatusCode::NOT_FOUND.into_response();
    }
    if req.uri().query().is_some() {
        return reply(
            StatusCode::BAD_REQUEST,
            json!({"error":"query parameters are not accepted"}),
        );
    }
    if ["origin", "mcp-session-id", "mcp-protocol-version"]
        .iter()
        .any(|h| req.headers().get_all(*h).iter().count() > 1)
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if let Some(origin) = req.headers().get("origin")
        && !origin.to_str().ok().is_some_and(|s| {
            s == app.config.public_url || app.config.origins.iter().any(|o| o == s)
        })
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let principal = match auth::authenticate(&app, &name, req.headers()).await {
        Ok(p) => p,
        Err(r) => return *r,
    };
    let (parts, body) = req.into_parts();
    if !matches!(parts.method, Method::POST | Method::GET | Method::DELETE) {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    if parts.method == Method::POST {
        if !parts
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.split(';').next() == Some("application/json"))
        {
            return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
        }
        let accept = parts
            .headers
            .get("accept")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !accept.contains("application/json") || !accept.contains("text/event-stream") {
            return StatusCode::NOT_ACCEPTABLE.into_response();
        }
    }
    let bytes = match to_bytes(body, 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    transport::forward(app, name, principal, parts.method, parts.headers, bytes).await
}
fn router(app: Arc<App>) -> Router {
    let mut routes = Router::new()
        .route(
            "/healthz",
            get(|| async {
                axum::Json(
                    json!({"status":"ok","service":"mcpmux","version":env!("CARGO_PKG_VERSION")}),
                )
            }),
        )
        .route(
            "/",
            get(|| async { "mcpmux — authenticated MCP path gateway\n" }),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(auth::metadata),
        )
        .route(
            "/.well-known/oauth-protected-resource/mcp/{name}",
            get(resource),
        )
        .route("/authorize", get(auth::authorize).post(auth::approve))
        .route("/token", post(auth::token))
        .route("/mcp/{name}", any(gateway));
    for (name, route) in &app.config.routes {
        if let Some(path) = &route.path {
            let route_name = name.clone();
            routes = routes.route(
                path,
                any(move |State(app): State<Arc<App>>, req: Request| {
                    gateway_for(app, route_name.clone(), req)
                }),
            );
            let metadata_name = name.clone();
            routes = routes.route(
                &format!("/.well-known/oauth-protected-resource{path}"),
                get(move |State(app): State<Arc<App>>| async move {
                    resource_for(&app, &metadata_name)
                }),
            );
        }
    }
    routes
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(middleware::from_fn(security))
        .with_state(app)
}
#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("secret") => {
            let path = args
                .get(2)
                .ok_or_else(|| anyhow::anyhow!("usage: mcpmux secret FILE"))?;
            let secret = auth::secret();
            write_private(FilePath::new(path), secret.as_bytes())?;
            println!("sha256 = \"{}\"", auth::hash(&secret));
            return Ok(());
        }
        Some("bootstrap") => {
            let dir = args
                .get(2)
                .ok_or_else(|| anyhow::anyhow!("usage: mcpmux bootstrap DIRECTORY HTTPS_ORIGIN"))?;
            let origin = args
                .get(3)
                .ok_or_else(|| anyhow::anyhow!("HTTPS origin required"))?;
            bootstrap(FilePath::new(dir), origin)?;
            return Ok(());
        }
        Some("demo-stdio") => {
            demo().await?;
            return Ok(());
        }
        _ => {}
    }
    let path = args
        .get(2)
        .filter(|_| matches!(args.get(1).map(String::as_str), Some("serve" | "check")))
        .map(String::as_str)
        .unwrap_or("/etc/mcpmux/mcpmux.toml");
    if !matches!(
        args.get(1).map(String::as_str),
        None | Some("serve" | "check")
    ) {
        anyhow::bail!(
            "commands: serve [CONFIG], check [CONFIG], secret FILE, bootstrap DIR HTTPS_ORIGIN, demo-stdio"
        )
    }
    let config = Config::load(FilePath::new(path))?;
    if args.get(1).map(String::as_str) == Some("check") {
        println!("configuration valid: {} routes", config.routes.len());
        return Ok(());
    }
    let listen = config.listen.clone();
    let app = Arc::new(App {
        config,
        auth: Mutex::default(),
        sessions: Mutex::default(),
        active: Arc::new(Semaphore::new(128)),
        http: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .pool_max_idle_per_host(2)
            .build()?,
    });
    let weak = Arc::downgrade(&app);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            let Some(app) = weak.upgrade() else { break };
            app.sessions.lock().await.retain(|_, s| {
                let keep = Instant::now().duration_since(s.touched)
                    < Duration::from_secs(app.config.session_idle_seconds);
                if !keep && let transport::Backend::Stdio(child) = &s.backend {
                    child.terminate();
                }
                keep
            });
            app.auth.lock().await.prune();
        }
    });
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    eprintln!(
        "mcpmux {} listening on {}",
        env!("CARGO_PKG_VERSION"),
        listen
    );
    axum::serve(listener, router(app))
        .with_graceful_shutdown(async {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
            tokio::select! {_=tokio::signal::ctrl_c()=>{},_=term.recv()=>{}}
        })
        .await?;
    Ok(())
}
fn write_private(path: &FilePath, data: &[u8]) -> anyhow::Result<()> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)?;
    Ok(())
}
fn bootstrap(dir: &FilePath, origin: &str) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    let password = auth::secret();
    let token = auth::secret();
    let exe = std::env::current_exe()?;
    let quote = |s: &str| toml::Value::String(s.into()).to_string();
    let config = format!(
        "public_url = {}\nlisten = \"127.0.0.1:8088\"\n\n[upstreams.demo]\ntype = \"stdio\"\ncommand = {}\nargs = [\"demo-stdio\"]\n\n[routes.demo]\nupstream = \"demo\"\n\n[routes.demo-alias]\nalias = \"demo\"\n\n[users.owner]\npassword_sha256 = \"{}\"\nroutes = [\"demo\", \"demo-alias\"]\n\n[clients.mcpmux-local]\nredirect_uris = [\"http://127.0.0.1:8765/callback\"]\nroutes = [\"demo\", \"demo-alias\"]\n\n[tokens.demo]\nsha256 = \"{}\"\nsubject = \"owner\"\nroute = \"demo\"\n",
        quote(origin),
        quote(&exe.to_string_lossy()),
        auth::hash(&password),
        auth::hash(&token)
    );
    let _: Config = toml::from_str(&config)?;
    write_private(&dir.join("mcpmux.toml"), config.as_bytes())?;
    write_private(&dir.join("owner-password"), password.as_bytes())?;
    write_private(&dir.join("demo-token"), token.as_bytes())?;
    println!(
        "Created {}. Secrets saved privately; no secrets printed.",
        dir.display()
    );
    Ok(())
}
async fn demo() -> anyhow::Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut out = tokio::io::stdout();
    while let Some(line) = lines.next_line().await? {
        let v: Value = serde_json::from_str(&line)?;
        if v.get("id").is_none() {
            continue;
        }
        let modern = v
            .pointer("/params/_meta/io.modelcontextprotocol~1protocolVersion")
            .and_then(Value::as_str)
            == Some("2026-07-28");
        let mut result = match v["method"].as_str() {
            Some("initialize") => {
                json!({"protocolVersion":v["params"]["protocolVersion"],"capabilities":{"tools":{}},"serverInfo":{"name":"mcpmux-demo","version":"0.1.0"}})
            }
            Some("server/discover") => {
                json!({"supportedVersions":["2026-07-28","2025-11-25"],"capabilities":{"tools":{}},"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"mcpmux-demo","version":"0.1.0"}}})
            }
            Some("ping") => json!({}),
            Some("tools/list") => {
                json!({"tools":[{"name":"echo","description":"Echo a message to verify gateway connectivity","inputSchema":{"type":"object","properties":{"message":{"type":"string"}},"required":["message"]}}]})
            }
            Some("tools/call") if v["params"]["name"] == "echo" => {
                json!({"content":[{"type":"text","text":v["params"]["arguments"]["message"].as_str().unwrap_or("")}]})
            }
            _ => {
                let r = json!({"jsonrpc":"2.0","id":v["id"],"error":{"code":-32601,"message":"Method not found"}});
                out.write_all(format!("{r}\n").as_bytes()).await?;
                out.flush().await?;
                continue;
            }
        };
        if modern {
            result["resultType"] = json!("complete");
        }
        let r = json!({"jsonrpc":"2.0","id":v["id"],"result":result});
        out.write_all(format!("{r}\n").as_bytes()).await?;
        out.flush().await?;
    }
    Ok(())
}
