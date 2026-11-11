use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::Poll;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use deno_core::{op2, OpState};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::{self, Message};

const SOCKET_LIMIT: usize = 8;
const INBOUND_LIMIT: usize = 512;
const OUTBOUND_BYTE_LIMIT: usize = 16 * 1024 * 1024;
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

#[derive(Debug)]
enum Outbound {
    Text(String),
    Binary(Vec<u8>),
    Close(u16, String),
}

#[derive(Debug)]
enum Inbound {
    Open(String),
    Text(String),
    Binary(Vec<u8>),
    Error,
    Close(u16, String),
}

struct Socket {
    outbound: mpsc::UnboundedSender<Outbound>,
    inbound: Rc<RefCell<mpsc::Receiver<Inbound>>>,
    queued_bytes: Arc<AtomicUsize>,
}

#[derive(Default)]
pub(crate) struct WsRegistry {
    next_id: u32,
    sockets: HashMap<u32, Socket>,
}

fn event_json(kind: &str) -> serde_json::Value {
    serde_json::json!({ "kind": kind })
}

fn error_json(message: impl AsRef<str>) -> String {
    serde_json::json!({"error": message.as_ref()}).to_string()
}

fn inbound_json(event: Inbound) -> String {
    let value = match event {
        Inbound::Open(protocol) => serde_json::json!({"kind":"open", "protocol":protocol}),
        Inbound::Text(data) => serde_json::json!({"kind":"message", "binary":false, "data":data}),
        Inbound::Binary(data) => serde_json::json!({"kind":"message", "binary":true, "data":BASE64.encode(data)}),
        Inbound::Error => event_json("error"),
        Inbound::Close(code, reason) => serde_json::json!({"kind":"close", "code":code, "reason":reason}),
    };
    value.to_string()
}

fn ws_http_url(url: &url::Url) -> Option<url::Url> {
    let mut translated = url.clone();
    translated.set_scheme(match url.scheme() { "ws" => "http", "wss" => "https", _ => return None }).ok()?;
    Some(translated)
}

fn origin_of(value: &str) -> String {
    url::Url::parse(value).map(|url| url.origin().ascii_serialization()).unwrap_or_default()
}

fn cookie_header(jar: &Option<Arc<obscura_net::CookieJar>>, url: &url::Url) -> String {
    jar.as_ref().and_then(|jar| ws_http_url(url).map(|url| jar.get_cookie_header(&url))).unwrap_or_default()
}

async fn dial_stream(target: std::net::SocketAddr, proxy: Option<&str>) -> Result<tokio::net::TcpStream, String> {
    match proxy {
        None => tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(target)).await
            .map_err(|_| "WebSocket TCP connection timed out".to_string())?
            .map_err(|error| format!("WebSocket TCP connection failed: {error}")),
        Some(proxy) if proxy.starts_with("socks5://") || proxy.starts_with("socks5h://") => {
            let authority = proxy.split_once("://").map(|(_, value)| value).unwrap_or(proxy);
            let target_authority = target.to_string();
            tokio::time::timeout(CONNECT_TIMEOUT, tokio_socks::tcp::socks5::Socks5Stream::connect(authority, target_authority.as_str()))
                .await.map_err(|_| "SOCKS proxy connection timed out".to_string())?
                .map(|stream| stream.into_inner()).map_err(|error| format!("SOCKS proxy connect failed: {error}"))
        }
        Some(proxy) if proxy.starts_with("http://") => {
            let proxy_url = url::Url::parse(proxy).map_err(|error| format!("invalid HTTP proxy URL: {error}"))?;
            let proxy_host = proxy_url.host_str().ok_or_else(|| "HTTP proxy URL has no host".to_string())?;
            let proxy_port = proxy_url.port_or_known_default().ok_or_else(|| "HTTP proxy URL has no port".to_string())?;
            let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect((proxy_host, proxy_port)))
                .await.map_err(|_| "HTTP proxy connection timed out".to_string())?
                .map_err(|error| format!("HTTP proxy connection failed: {error}"))?;
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let authority = target.to_string();
            stream.write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes()).await
                .map_err(|error| format!("HTTP proxy CONNECT failed: {error}"))?;
            let (mut read, mut write) = stream.into_split();
            let mut response = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                let count = read.read(&mut byte).await.map_err(|error| format!("HTTP proxy CONNECT failed: {error}"))?;
                if count == 0 { return Err("HTTP proxy closed the CONNECT tunnel".to_string()); }
                response.push(byte[0]);
                if response.ends_with(b"\r\n\r\n") { break; }
                if response.len() > 16 * 1024 { return Err("HTTP proxy CONNECT response too large".to_string()); }
            }
            let status = response.split(|byte| *byte == b' ').nth(1).unwrap_or_default();
            if status != b"200" { return Err(format!("HTTP proxy CONNECT refused (status {})", String::from_utf8_lossy(status))); }
            Ok(read.unsplit(write))
        }
        Some(proxy) => Err(format!("Unsupported WebSocket proxy scheme in '{proxy}'")),
    }
}

async fn connect_task(
    url: url::Url,
    protocols: Vec<String>,
    origin: String,
    user_agent: String,
    accept_language: String,
    cookie: String,
    extra_headers: HashMap<String, String>,
    allow_private: bool,
    proxy_url: Option<String>,
    inbound: mpsc::Sender<Inbound>,
    mut outbound: mpsc::UnboundedReceiver<Outbound>,
    queued_bytes: Arc<AtomicUsize>,
) {
    let result = async {
        if !matches!(url.scheme(), "ws" | "wss") {
            return Err("unsupported WebSocket scheme".to_string());
        }
        let host = url.host_str().ok_or_else(|| "WebSocket URL has no host".to_string())?.to_string();
        let port = url.port_or_known_default().ok_or_else(|| "WebSocket URL has no port".to_string())?;
        let allow_private = allow_private || obscura_net::env_allows_private_network();
        let addresses: Vec<_> = tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::lookup_host((host.as_str(), port))).await
            .map_err(|_| "WebSocket DNS resolution timed out".to_string())?
            .map_err(|error| format!("DNS resolution failed: {error}"))?.collect();
        if addresses.is_empty() {
            return Err("DNS resolution returned no addresses".to_string());
        }
        if !allow_private {
            if let Some(forbidden) = addresses.iter().find(|address| obscura_net::is_forbidden_ip(address.ip())) {
                return Err(format!("SSRF blocked: WebSocket host resolves to forbidden address {}", forbidden.ip()));
            }
        }
        let target = addresses[0];
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, dial_stream(target, proxy_url.as_deref())).await
            .map_err(|_| "WebSocket proxy tunnel timed out".to_string())??;
        let mut request = tungstenite::http::Request::builder().uri(url.as_str());
        let headers = request.headers_mut().ok_or_else(|| "invalid WebSocket request".to_string())?;
        let set_header = |headers: &mut tungstenite::http::HeaderMap, name: &str, value: &str| -> Result<(), String> {
            if !value.is_empty() {
                headers.insert(tungstenite::http::header::HeaderName::from_bytes(name.as_bytes()).map_err(|e| e.to_string())?,
                    tungstenite::http::HeaderValue::from_str(value).map_err(|e| e.to_string())?);
            }
            Ok(())
        };
        set_header(headers, "origin", &origin)?;
        set_header(headers, "user-agent", &user_agent)?;
        set_header(headers, "accept-language", &accept_language)?;
        set_header(headers, "cookie", &cookie)?;
        if !protocols.is_empty() { set_header(headers, "sec-websocket-protocol", &protocols.join(", "))?; }
        for (name, value) in extra_headers {
            if matches!(name.to_ascii_lowercase().as_str(), "host" | "upgrade" | "connection" | "sec-websocket-key" | "sec-websocket-version" | "sec-websocket-protocol" | "origin" | "cookie") { continue; }
            set_header(headers, &name, &value)?;
        }
        let request = request.body(()).map_err(|error| format!("invalid WebSocket request: {error}"))?;
        let (mut socket, response) = tokio::time::timeout(CONNECT_TIMEOUT,
            tokio_tungstenite::client_async_tls_with_config(request, stream, None, None))
            .await.map_err(|_| "WebSocket handshake timed out".to_string())?
            .map_err(|error| format!("WebSocket handshake failed: {error}"))?;
        let protocol = response.headers().get("sec-websocket-protocol").and_then(|value| value.to_str().ok()).unwrap_or("").to_string();
        inbound.send(Inbound::Open(protocol)).await.map_err(|_| "page closed".to_string())?;
        loop {
            tokio::select! {
                outgoing = outbound.recv() => match outgoing {
                    Some(Outbound::Text(text)) => {
                        queued_bytes.fetch_sub(text.len(), Ordering::Relaxed);
                        socket.send(Message::Text(text.into())).await.map_err(|e| e.to_string())?;
                    }
                    Some(Outbound::Binary(bytes)) => {
                        queued_bytes.fetch_sub(bytes.len(), Ordering::Relaxed);
                        socket.send(Message::Binary(bytes.into())).await.map_err(|e| e.to_string())?;
                    }
                    Some(Outbound::Close(code, reason)) => {
                        let close = tungstenite::protocol::frame::CloseFrame {
                            code: tungstenite::protocol::frame::coding::CloseCode::from(code),
                            reason: reason.into(),
                        };
                        let _ = socket.send(Message::Close(Some(close))).await;
                    }
                    None => return Ok(()),
                },
                incoming = socket.next() => match incoming {
                    Some(Ok(Message::Text(text))) => if inbound.send(Inbound::Text(text.to_string())).await.is_err() { return Ok(()); },
                    Some(Ok(Message::Binary(bytes))) => if inbound.send(Inbound::Binary(bytes.to_vec())).await.is_err() { return Ok(()); },
                    Some(Ok(Message::Ping(payload))) => { socket.send(Message::Pong(payload)).await.map_err(|e| e.to_string())?; }
                    Some(Ok(Message::Pong(_))) | Some(Ok(Message::Frame(_))) => {},
                    Some(Ok(Message::Close(frame))) => {
                        let (code, reason) = frame.map(|frame| (u16::from(frame.code), frame.reason.to_string())).unwrap_or((1005, String::new()));
                        let _ = inbound.send(Inbound::Close(code, reason)).await;
                        return Ok(());
                    }
                    Some(Err(_)) | None => { let _ = inbound.send(Inbound::Error).await; let _ = inbound.send(Inbound::Close(1006, String::new())).await; return Ok(()); }
                }
            }
        }
    }.await;
    if let Err(error) = result {
        let _ = inbound.send(Inbound::Error).await;
        let _ = inbound.send(Inbound::Close(1006, error)).await;
    }
}

#[op2]
#[string]
pub(crate) async fn op_ws_open(state: Rc<RefCell<OpState>>, #[string] url: String, #[string] protocols_json: String) -> String {
    let parsed = match url::Url::parse(&url) {
        Ok(url) if matches!(url.scheme(), "ws" | "wss") && url.host_str().is_some()
            && url.username().is_empty() && url.password().is_none() && url.fragment().is_none() => url,
        _ => return error_json("Invalid WebSocket URL"),
    };
    let owner = state.borrow().borrow::<Rc<RefCell<crate::ops::ObscuraState>>>().clone();
    let (page_url, cookie, client, allow_private, proxy_url) = {
        let page = owner.borrow();
        if page.blocked_urls.iter().any(|pattern| pattern == "*" || url.contains(pattern) || crate::ops::glob_match(pattern, &url)) {
            return error_json("Blocked by Network.setBlockedURLs");
        }
        (page.url.clone(), cookie_header(&page.cookie_jar, &parsed), page.http_client.clone(),
            page.http_client.as_ref().is_some_and(|client| client.allow_private_network),
            page.http_client.as_ref().and_then(|client| client.proxy_url().map(str::to_owned)))
    };
    let (user_agent, accept_language, extra_headers) = if let Some(client) = client {
        tokio::join!(
            async { client.user_agent.read().await.clone() },
            async { client.accept_language.read().await.clone() },
            async { client.extra_headers.read().await.clone() },
        )
    } else {
        (String::new(), String::new(), HashMap::new())
    };
    let protocols: Vec<String> = serde_json::from_str(&protocols_json).unwrap_or_default();
    let mut page = owner.borrow_mut();
    if page.ws_registry.sockets.len() >= SOCKET_LIMIT { return error_json("Too many open WebSocket connections"); }
    page.ws_registry.next_id = page.ws_registry.next_id.wrapping_add(1).max(1);
    let id = page.ws_registry.next_id;
    let (outbound_tx, outbound_rx) = mpsc::unbounded_channel();
    let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_LIMIT);
    let inbound = Rc::new(RefCell::new(inbound_rx));
    let queued_bytes = Arc::new(AtomicUsize::new(0));
    page.ws_registry.sockets.insert(id, Socket { outbound: outbound_tx, inbound, queued_bytes: queued_bytes.clone() });
    let origin = origin_of(&page_url);
    tokio::spawn(connect_task(parsed, protocols, origin, user_agent, accept_language, cookie, extra_headers, allow_private, proxy_url, inbound_tx, outbound_rx, queued_bytes));
    serde_json::json!({"id":id}).to_string()
}

#[op2]
#[string]
pub(crate) async fn op_ws_next_message(state: Rc<RefCell<OpState>>, id: u32) -> String {
    let owner = state.borrow().borrow::<Rc<RefCell<crate::ops::ObscuraState>>>().clone();
    let inbound = owner.borrow().ws_registry.sockets.get(&id).map(|socket| socket.inbound.clone());
    let Some(inbound) = inbound else { return inbound_json(Inbound::Close(1006, String::new())); };
    let event = std::future::poll_fn(|cx| match inbound.borrow_mut().poll_recv(cx) {
        Poll::Ready(Some(event)) => Poll::Ready(event),
        Poll::Ready(None) => Poll::Ready(Inbound::Close(1006, String::new())),
        Poll::Pending => Poll::Pending,
    }).await;
    if matches!(&event, Inbound::Close(..)) { owner.borrow_mut().ws_registry.sockets.remove(&id); }
    inbound_json(event)
}

#[op2(fast)]
pub(crate) fn op_ws_send(state: &OpState, id: u32, #[string] kind: &str, #[string] payload: &str) -> bool {
    let owner = state.borrow::<Rc<RefCell<crate::ops::ObscuraState>>>().clone();
    let page = owner.borrow();
    let Some(socket) = page.ws_registry.sockets.get(&id) else { return false; };
    let (message, size) = if kind == "binary" {
        let Ok(bytes) = BASE64.decode(payload) else { return false; };
        let size = bytes.len();
        (Outbound::Binary(bytes), size)
    } else {
        (Outbound::Text(payload.to_string()), payload.len())
    };
    let next = socket.queued_bytes.fetch_add(size, Ordering::Relaxed).saturating_add(size);
    if next > OUTBOUND_BYTE_LIMIT {
        socket.queued_bytes.fetch_sub(size, Ordering::Relaxed);
        return false;
    }
    if socket.outbound.send(message).is_err() {
        socket.queued_bytes.fetch_sub(size, Ordering::Relaxed);
        return false;
    }
    true
}

#[op2(fast)]
pub(crate) fn op_ws_close(state: &OpState, id: u32, code: u16, #[string] reason: &str) {
    let owner = state.borrow::<Rc<RefCell<crate::ops::ObscuraState>>>().clone();
    if let Some(socket) = owner.borrow().ws_registry.sockets.get(&id) {
        let _ = socket.outbound.send(Outbound::Close(code, reason.to_string()));
    }
}
