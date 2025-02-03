use base64_simd::URL_SAFE_NO_PAD;
use hyper::service::{make_service_fn, service_fn};
use hyper::{header, Body, Request, Response, Server, StatusCode, Uri};
use sha2::{Digest, Sha256};
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _ = dotenvy::dotenv();

    let private_key = env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set");
    let target_url = env::var("TARGET_URL")
        .expect("TARGET_URL must be set")
        .parse::<Uri>()
        .expect("Invalid TARGET_URL");

    let client = hyper::Client::new();

    let make_svc = make_service_fn(move |_| {
        let client = client.clone();
        let private_key = private_key.clone();
        let target_url = target_url.clone();

        async move {
            Ok::<_, hyper::Error>(service_fn(move |mut req| {
                let client = client.clone();
                let private_key = private_key.clone();
                let target_url = target_url.clone();

                async move {
                    let user_id = match validate_auth(&req, &private_key).await {
                        Ok(id) => id,
                        Err(res) => return Ok(res),
                    };

                    let path = req
                        .uri()
                        .path_and_query()
                        .map(|p| p.as_str())
                        .unwrap_or("/");
                    // let target = format!("{}{}", target_url, path);
                    *req.uri_mut() = Uri::builder()
                        .scheme(target_url.scheme().unwrap().as_str())
                        .authority(target_url.authority().unwrap().as_str())
                        .path_and_query(path)
                        .build()
                        .unwrap();

                    // Set X-Scope-OrgID header
                    req.headers_mut().insert(
                        header::HeaderName::from_static("X-Scope-OrgID"),
                        user_id.parse().unwrap(),
                    );

                    client.request(req).await
                }
            }))
        }
    });

    let addr = ([0, 0, 0, 0], 3000).into();
    let server = Server::bind(&addr).serve(make_svc);

    println!("Listening on {}", addr);
    server.await?;
    Ok(())
}

async fn validate_auth(req: &Request<Body>, private_key: &str) -> Result<String, Response<Body>> {
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| unauthorized_response("Missing Authorization header"))?;

    let (user_id, password) = parse_basic_auth(auth_header)
        .map_err(|_| unauthorized_response("Invalid Authorization header format"))?;

    let mut hasher = Sha256::new();
    hasher.update(private_key.as_bytes());
    hasher.update(user_id.as_bytes());
    let expected = URL_SAFE_NO_PAD.encode_to_string(hasher.finalize());

    if password != expected {
        return Err(unauthorized_response("Invalid credentials"));
    }

    Ok(user_id.to_string())
}

fn parse_basic_auth(header: &str) -> Result<(String, String), ()> {
    let stripped = header.strip_prefix("Basic ").ok_or(())?;
    let decoded = URL_SAFE_NO_PAD
        .decode_to_vec(stripped.as_bytes())
        .map_err(|_| ())?;
    let credentials = String::from_utf8(decoded).map_err(|_| ())?;
    let mut parts = credentials.splitn(2, ':');

    match (parts.next(), parts.next()) {
        (Some(user), Some(pass)) => Ok((user.to_string(), pass.to_string())),
        _ => Err(()),
    }
}

fn unauthorized_response(message: &str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::WWW_AUTHENTICATE, "Basic realm=\"Restricted\"")
        .body(Body::from(message.to_string()))
        .unwrap()
}
