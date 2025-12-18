use base64_simd::{STANDARD, STANDARD_NO_PAD};
use hyper::service::{make_service_fn, service_fn};
use hyper::{header, Body, Method, Request, Response, Server, StatusCode, Uri};
use sha2::{Digest, Sha256};
use std::convert::Infallible;
use std::env;
use std::fs;
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _ = dotenvy::dotenv();

    let auth_salt = read_secret("AUTH_SALT")
        .or_else(|_| read_secret("PRIVATE_KEY"))
        .map_err(|_| "Missing AUTH_SALT (or legacy PRIVATE_KEY)")?;
    let admin_key = read_secret("ADMIN_KEY").map_err(|_| "Missing ADMIN_KEY")?;
    let target_url = env::var("TARGET_URL")?.parse::<Uri>()?;
    let listen_addr = env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:3000".to_string())
        .parse::<SocketAddr>()?;

    let client = hyper::Client::new();

    let make_svc = make_service_fn(move |_| {
        let client = client.clone();
        let auth_salt = auth_salt.clone();
        let admin_key = admin_key.clone();
        let target_url = target_url.clone();

        async move {
            Ok::<_, Infallible>(service_fn(move |mut req| {
                let client = client.clone();
                let auth_salt = auth_salt.clone();
                let admin_key = admin_key.clone();
                let target_url = target_url.clone();

                async move {
                    let path = req.uri().path();

                    if path == "/ready" || path == "/healthz" {
                        return Ok::<_, Infallible>(Response::new(Body::from("OK\n")));
                    }

                    if path == "/admin" || path.starts_with("/admin/") {
                        return Ok::<_, Infallible>(handle_admin(&req, &auth_salt, &admin_key));
                    }

                    let org_id = match get_org_id(&req) {
                        Ok(v) => v,
                        Err(res) => return Ok::<_, Infallible>(res),
                    };

                    if let Err(res) = validate_org_auth(&req, &auth_salt, &org_id) {
                        return Ok::<_, Infallible>(res);
                    }

                    // Build target URI with proper error handling
                    let new_uri = match build_target_uri(&target_url, req.uri()) {
                        Ok(uri) => uri,
                        Err(msg) => return Ok(internal_server_error(&msg)),
                    };
                    *req.uri_mut() = new_uri;

                    req.headers_mut()
                        .insert(header::HOST, authority_to_host_header(&target_url));
                    req.headers_mut().remove(header::AUTHORIZATION);
                    set_scope_orgid(&mut req, &org_id);
                    
                    match client.request(req).await {
                        Ok(res) => Ok(res),
                        Err(e) => Ok(internal_server_error(&format!("Upstream request failed: {e}"))),
                    }
                }
            }))
        }
    });

    let server = Server::bind(&listen_addr).serve(make_svc);

    println!("Listening on {}", listen_addr);
    server.await?;
    Ok(())
}

fn get_org_id(req: &Request<Body>) -> Result<String, Response<Body>> {
    for name in ["xorgid", "x-orgid", "x-scope-orgid"] {
        if let Some(v) = req.headers().get(name).and_then(|v| v.to_str().ok()) {
            let v = v.trim();
            if !v.is_empty() {
                return Ok(v.to_string());
            }
        }
    }
    Err(bad_request("Missing xorgid header (xorgid, x-orgid, or x-scope-orgid)"))
}

fn set_scope_orgid(req: &mut Request<Body>, org_id: &str) {
    let header_value = match header::HeaderValue::from_str(org_id) {
        Ok(v) => v,
        Err(_) => return,
    };
    req.headers_mut().insert(
        header::HeaderName::from_static("x-scope-orgid"),
        header_value,
    );
}

fn validate_org_auth(req: &Request<Body>, auth_salt: &str, org_id: &str) -> Result<(), Response<Body>> {
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| unauthorized_response("Missing Authorization header"))?;

    let (user, password) = parse_basic_auth(auth_header)
        .map_err(|_| unauthorized_response("Invalid Authorization header format"))?;

    if user != org_id {
        return Err(unauthorized_response("Username must match xorgid header"));
    }

    let expected = derive_key(auth_salt, org_id);
    if password != expected {
        return Err(unauthorized_response("Invalid credentials"));
    }

    Ok(())
}

fn parse_basic_auth(header: &str) -> Result<(String, String), ()> {
    let stripped = header.strip_prefix("Basic ").ok_or(())?;
    let decoded = STANDARD
        .decode_to_vec(stripped.as_bytes())
        .or_else(|_| STANDARD_NO_PAD.decode_to_vec(stripped.as_bytes()))
        .map_err(|_| ())?;
    let credentials = String::from_utf8(decoded).map_err(|_| ())?;
    let mut parts = credentials.splitn(2, ':');

    match (parts.next(), parts.next()) {
        (Some(user), Some(pass)) => Ok((user.to_string(), pass.to_string())),
        _ => Err(()),
    }
}

fn handle_admin(req: &Request<Body>, auth_salt: &str, admin_key: &str) -> Response<Body> {
    if let Err(res) = validate_admin_auth(req, admin_key) {
        return res;
    }

    match (req.method(), req.uri().path()) {
        (&Method::GET, "/admin") => admin_page(),
        (&Method::GET, "/admin/sign") => admin_sign(req, auth_salt),
        _ => not_found(),
    }
}

fn validate_admin_auth(req: &Request<Body>, admin_key: &str) -> Result<(), Response<Body>> {
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| unauthorized_response("Missing Authorization header"))?;

    let (user, password) = parse_basic_auth(auth_header)
        .map_err(|_| unauthorized_response("Invalid Authorization header format"))?;

    if user != "admin" || password != admin_key {
        return Err(unauthorized_response("Invalid admin credentials"));
    }

    Ok(())
}

fn admin_sign(req: &Request<Body>, auth_salt: &str) -> Response<Body> {
    let org_id = match query_param(req.uri(), "orgid") {
        Some(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => return bad_request("Missing orgid query parameter"),
    };

    let key = derive_key(auth_salt, &org_id);
    let body = format!(
        "{{\"orgid\":{},\"key\":{}}}\n",
        json_string(&org_id),
        json_string(&key)
    );

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(body))
        .expect("Valid response")
}

fn admin_page() -> Response<Body> {
    let html = r#"<!doctype html>
<meta charset="utf-8" />
<title>amimir admin</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 2rem; max-width: 48rem; }
  input { padding: 0.5rem; width: 24rem; }
  button { padding: 0.55rem 1rem; }
  pre { padding: 1rem; background: #111; color: #ddd; overflow: auto; }
</style>
<h1>amimir admin</h1>
<p>Generate an org key (username = orgid, password = derived key).</p>
<div>
  <label>orgid: <input id="orgid" placeholder="example-org" /></label>
  <button id="go">Sign</button>
</div>
<pre id="out">Enter an orgid and click Sign.</pre>
<script>
  const orgid = document.getElementById('orgid');
  const out = document.getElementById('out');
  document.getElementById('go').addEventListener('click', async () => {
    out.textContent = '...';
    const v = (orgid.value || '').trim();
    if (!v) { out.textContent = 'Missing orgid'; return; }
    const res = await fetch('/admin/sign?orgid=' + encodeURIComponent(v));
    const text = await res.text();
    if (!res.ok) { out.textContent = text; return; }
    try {
      const j = JSON.parse(text);
      out.textContent = 'orgid: ' + j.orgid + '\\nkey: ' + j.key;
    } catch {
      out.textContent = text;
    }
  });
</script>
"#;

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(html))
        .expect("Valid response")
}

fn derive_key(auth_salt: &str, org_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(auth_salt.as_bytes());
    hasher.update(b":");
    hasher.update(org_id.as_bytes());
    let hash = hasher.finalize();
    let mut out = String::with_capacity(hash.len() * 2);
    for b in hash {
        out.push(hex_digit(b >> 4));
        out.push(hex_digit(b & 0x0f));
    }
    out
}

fn hex_digit(v: u8) -> char {
    match v {
        0..=9 => (b'0' + v) as char,
        10..=15 => (b'a' + (v - 10)) as char,
        _ => '?',
    }
}

fn query_param(uri: &Uri, key: &str) -> Option<String> {
    let query = uri.query()?;
    for part in query.split('&') {
        let mut it = part.splitn(2, '=');
        let k = it.next()?;
        let v = it.next().unwrap_or("");
        if k == key {
            return Some(url_decode(v));
        }
    }
    None
}

fn url_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut bytes = s.as_bytes().iter().copied();
    while let Some(b) = bytes.next() {
        if b == b'+' {
            out.push(' ');
            continue;
        }
        if b != b'%' {
            out.push(b as char);
            continue;
        }
        let h1 = match bytes.next() {
            Some(v) => v,
            None => break,
        };
        let h2 = match bytes.next() {
            Some(v) => v,
            None => break,
        };
        if let (Some(v1), Some(v2)) = (from_hex(h1), from_hex(h2)) {
            out.push((v1 << 4 | v2) as char);
        }
    }
    out
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str("\\uFFFD"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn unauthorized_response(message: &str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(
            header::WWW_AUTHENTICATE,
            header::HeaderValue::from_static("Basic realm=\"Restricted\""),
        )
        .body(Body::from(message.to_string()))
        .expect("Valid response")
}

fn bad_request(message: &str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(Body::from(message.to_string()))
        .expect("Valid response")
}

fn not_found() -> Response<Body> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::from("Not Found\n"))
        .expect("Valid response")
}

fn internal_server_error(message: &str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(Body::from(message.to_string()))
        .expect("Valid response")
}

fn build_target_uri(target_base: &Uri, incoming: &Uri) -> Result<Uri, String> {
    let scheme = target_base
        .scheme()
        .ok_or_else(|| "Target URL missing scheme".to_string())?
        .as_str();
    let authority = target_base
        .authority()
        .ok_or_else(|| "Target URL missing authority".to_string())?
        .as_str();

    let base_path = target_base.path().trim_end_matches('/');
    let in_path = incoming.path().trim_start_matches('/');
    let mut path = String::new();
    if base_path.is_empty() {
        path.push('/');
        path.push_str(in_path);
    } else {
        path.push_str(base_path);
        path.push('/');
        path.push_str(in_path);
    }
    if path.is_empty() {
        path.push('/');
    }

    if let Some(q) = incoming.query() {
        path.push('?');
        path.push_str(q);
    }

    Uri::builder()
        .scheme(scheme)
        .authority(authority)
        .path_and_query(path)
        .build()
        .map_err(|e| format!("Failed to build URI: {e}"))
}

fn authority_to_host_header(target_base: &Uri) -> header::HeaderValue {
    target_base
        .authority()
        .map(|a| a.as_str())
        .and_then(|v| header::HeaderValue::from_str(v).ok())
        .unwrap_or_else(|| header::HeaderValue::from_static("localhost"))
}

fn read_secret(name: &str) -> Result<String, ()> {
    if let Ok(v) = env::var(format!("{name}_FILE")) {
        let content = fs::read_to_string(v).map_err(|_| ())?;
        let trimmed = content.trim();
        if trimmed.is_empty() {
            return Err(());
        }
        return Ok(trimmed.to_string());
    }

    let v = env::var(name).map_err(|_| ())?;
    let trimmed = v.trim();
    if trimmed.is_empty() {
        return Err(());
    }
    Ok(trimmed.to_string())
}
