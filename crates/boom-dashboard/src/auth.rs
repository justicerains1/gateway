use crate::state::DashboardState;
use axum::extract::FromRequestParts;
use axum::http::header::{COOKIE, ORIGIN, SET_COOKIE};
use axum::http::request::Parts;
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

pub async fn verify_origin(
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    let public_mode = std::env::var("BOOM_PUBLIC_MODE").as_deref() == Ok("true");
    let expected = std::env::var("BOOM_DASHBOARD_PUBLIC_ORIGIN").unwrap_or_default();
    let actual = request.headers().get(ORIGIN).and_then(|value| value.to_str().ok());
    if !origin_allowed(
        request.method(), request.uri().path(), actual, public_mode, &expected,
    ) {
        return (StatusCode::FORBIDDEN, "Invalid request origin").into_response();
    }
    next.run(request).await
}

fn origin_allowed(method: &Method, path: &str, actual: Option<&str>, public_mode: bool, expected: &str) -> bool {
    if !public_mode || !path.starts_with("/dashboard/api/") {
        return true;
    }
    if matches!(*method, Method::POST | Method::PUT | Method::PATCH | Method::DELETE) {
        return actual == Some(expected);
    }
    true
}

#[cfg(test)]
mod origin_tests {
    use super::*;

    #[test]
    fn public_dashboard_writes_require_exact_origin() {
        let path = "/dashboard/api/admin/keys";
        let expected = "https://gateway.example.com";
        assert!(origin_allowed(&Method::POST, path, Some(expected), true, expected));
        assert!(!origin_allowed(&Method::POST, path, None, true, expected));
        assert!(!origin_allowed(&Method::PUT, path, Some("https://other.example.com"), true, expected));
        assert!(origin_allowed(&Method::GET, path, None, true, expected));
        assert!(origin_allowed(&Method::POST, "/v1/chat/completions", None, true, expected));
    }
}

// ── Login rate-limit constants ─────────────────────────────

/// Failures before the first lockout.
const MAX_LOGIN_FAILURES: u32 = 5;
/// Lockout duration on the first lockout trigger (6th failure).
const INITIAL_LOCKOUT: Duration = Duration::from_secs(10);
/// Additional lockout per subsequent failure after initial lockout.
const PER_FAILURE_LOCKOUT: Duration = Duration::from_secs(30);

// ── JWT Claims ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardClaims {
    /// "admin" or user_id.
    pub sub: String,
    /// "admin" | "user".
    pub role: String,
    /// User's token hash (empty for admin).
    pub key_hash: String,
    pub account_id: Option<uuid::Uuid>,
    pub exp: i64,
    pub iat: i64,
}

const SESSION_COOKIE_NAME: &str = "boom_session";
const SESSION_DURATION_SECS: i64 = 7200; // 2 hours

// ── Session Extractor ──────────────────────────────────────

/// Extractor that reads the session cookie and verifies the JWT.
#[derive(Debug, Clone)]
pub struct DashboardSession {
    pub claims: DashboardClaims,
}

impl<S: Send + Sync> FromRequestParts<S> for DashboardSession {
    type Rejection = Response;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        let result = extract_session(parts);
        std::future::ready(result)
    }
}

fn extract_session(parts: &mut Parts) -> Result<DashboardSession, Response> {
    let state = parts
        .extensions
        .get::<std::sync::Arc<DashboardState>>()
        .cloned()
        .ok_or_else(|| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "DashboardState not found",
            )
                .into_response()
        })?;

    let cookie_header = parts
        .headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|cookie| {
            let cookie = cookie.trim();
            let (name, value) = cookie.split_once('=')?;
            if name.trim() == SESSION_COOKIE_NAME {
                Some(value.trim().to_string())
            } else {
                None
            }
        })
        .ok_or_else(|| {
            (axum::http::StatusCode::UNAUTHORIZED, "No session cookie").into_response()
        })?;

    let token_data = decode::<DashboardClaims>(
        &cookie_header,
        &DecodingKey::from_secret(state.jwt_secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|_| {
        (axum::http::StatusCode::UNAUTHORIZED, "Invalid session").into_response()
    })?;

    Ok(DashboardSession {
        claims: token_data.claims,
    })
}

// ── Admin Session Extractor ────────────────────────────────

/// Extractor that requires admin role.
pub struct AdminSession {
    pub claims: DashboardClaims,
}

impl<S: Send + Sync> FromRequestParts<S> for AdminSession {
    type Rejection = Response;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        let result = extract_session(parts).and_then(|session| {
            if session.claims.role == "admin" {
                Ok(AdminSession {
                    claims: session.claims,
                })
            } else {
                Err(
                    (axum::http::StatusCode::FORBIDDEN, "Admin access required")
                        .into_response(),
                )
            }
        });
        std::future::ready(result)
    }
}

// ── Login Request ──────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub user_id: String,
    #[serde(default)]
    pub api_key: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub invite_code: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub role: String,
    pub user_id: String,
    /// Original API key, returned only for user logins so the dashboard chat
    /// window can call /v1/chat/completions with a Bearer header. None for admin.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
    pub invite_code: String,
}

pub async fn register(
    Extension(state): Extension<std::sync::Arc<DashboardState>>,
    Json(req): Json<RegisterRequest>,
) -> Response {
    let pool = match &state.db_pool { Some(pool) => pool, None => return json_error_response(StatusCode::SERVICE_UNAVAILABLE, "Database not available") };
    if req.username.len() < 3 || req.username.len() > 64 || req.password.len() < 8 {
        return json_error_response(StatusCode::BAD_REQUEST, "Username must be 3-64 chars and password at least 8 chars");
    }
    let mut tx = match pool.begin().await { Ok(tx) => tx, Err(_) => return json_error_response(StatusCode::INTERNAL_SERVER_ERROR, "Database error") };
    let invitation = sqlx::query_as::<_, (i32, i32, Option<chrono::DateTime<Utc>>)>("SELECT max_uses, used_count, expires_at FROM boom_invitation WHERE code = $1 FOR UPDATE")
        .bind(&req.invite_code).fetch_optional(&mut *tx).await;
    let Some((max_uses, used_count, expires_at)) = invitation.ok().flatten() else { return json_error_response(StatusCode::BAD_REQUEST, "Invalid invitation code"); };
    if used_count >= max_uses || expires_at.is_some_and(|at| at < Utc::now()) { return json_error_response(StatusCode::BAD_REQUEST, "Invitation code is exhausted or expired"); }
    let account_id = uuid::Uuid::new_v4();
    let salt = uuid::Uuid::new_v4().to_string();
    let password_hash = hash_password(&salt, &req.password);
    if sqlx::query("INSERT INTO boom_account(id, username, password_hash) VALUES ($1,$2,$3)").bind(account_id).bind(&req.username).bind(format!("{salt}${password_hash}")).execute(&mut *tx).await.is_err() {
        return json_error_response(StatusCode::CONFLICT, "Username already exists");
    }
    if sqlx::query("UPDATE boom_invitation SET used_count = used_count + 1 WHERE code = $1").bind(&req.invite_code).execute(&mut *tx).await.is_err() { return json_error_response(StatusCode::INTERNAL_SERVER_ERROR, "Failed to consume invitation"); }
    let raw_key = format!("sk-{}", uuid::Uuid::new_v4().simple());
    let token_hash = hash_token(&raw_key);
    if sqlx::query("INSERT INTO boom_verification_token(token,key_name,key_alias,user_id,account_id,models,spend,blocked) VALUES ($1,$2,$2,$3,$4,'{}',0,false)").bind(&token_hash).bind(&req.username).bind(&req.username).bind(account_id).execute(&mut *tx).await.is_err() { return json_error_response(StatusCode::INTERNAL_SERVER_ERROR, "Failed to create account key"); }
    if tx.commit().await.is_err() { return json_error_response(StatusCode::INTERNAL_SERVER_ERROR, "Failed to create account"); }
    sign_and_respond(&state, req.username, "user".to_string(), token_hash, Some(raw_key), Some(account_id))
}

#[derive(Debug, Serialize)]
pub struct MeResponse {
    pub user_id: String,
    pub role: String,
}

// ── IP Extraction ─────────────────────────────────────────

/// Extract client IP from request headers (reverse-proxy aware).
fn extract_client_ip(
    headers: &axum::http::HeaderMap,
    peer: Option<std::net::IpAddr>,
) -> String {
    if std::env::var("BOOM_PUBLIC_MODE").as_deref() == Ok("true") {
        let trusted = std::env::var("BOOM_TRUSTED_PROXY_IPS")
            .unwrap_or_default()
            .split(',')
            .filter_map(|value| value.trim().parse::<std::net::IpAddr>().ok())
            .any(|address| Some(address) == peer);
        if !trusted {
            return peer.map_or_else(|| "unknown".to_string(), |address| address.to_string());
        }
    }
    // Try X-Real-IP first (set by nginx etc.)
    if let Some(val) = headers.get("X-Real-IP").and_then(|v| v.to_str().ok()) {
        let ip = val.trim();
        if !ip.is_empty() {
            return ip.to_string();
        }
    }
    // Try X-Forwarded-For (first IP in the list).
    if let Some(val) = headers.get("X-Forwarded-For").and_then(|v| v.to_str().ok()) {
        if let Some(ip) = val.split(',').next() {
            let ip = ip.trim();
            if !ip.is_empty() {
                return ip.to_string();
            }
        }
    }
    "unknown".to_string()
}

// ── Login Rate Limiting ───────────────────────────────────

/// Check if an IP is currently locked out. Returns remaining lockout time if locked.
/// If the lockout has expired, resets the counter so the IP gets a fresh start.
fn check_login_lockout(state: &DashboardState, client_ip: &str) -> Option<Duration> {
    let map = &state.login_attempts;
    if let Some(entry) = map.get(client_ip) {
        if let Some(locked_until) = entry.locked_until {
            let now = Instant::now();
            if now < locked_until {
                return Some(locked_until - now);
            }
            // Lockout expired — remove entry to reset fail_count.
            drop(entry);
            map.remove(client_ip);
        }
    }
    None
}

/// Record a failed login attempt.
///
/// Lockout strategy:
///   - Failures 1..5: no lockout.
///   - 6th failure: lock for INITIAL_LOCKOUT (10s).
///   - Each subsequent failure extends lockout by PER_FAILURE_LOCKOUT (30s).
fn record_login_failure(state: &DashboardState, client_ip: &str) -> bool {
    let map = &state.login_attempts;
    let now = Instant::now();

    map.entry(client_ip.to_string())
        .and_modify(|attempt| {
            attempt.fail_count += 1;
            if attempt.fail_count >= MAX_LOGIN_FAILURES {
                let extra = if attempt.fail_count == MAX_LOGIN_FAILURES {
                    INITIAL_LOCKOUT
                } else {
                    PER_FAILURE_LOCKOUT
                };
                attempt.locked_until = Some(
                    attempt.locked_until.map_or(now, |t| t.max(now)) + extra,
                );
            }
        })
        .or_insert(crate::state::LoginAttempt {
            fail_count: 1,
            locked_until: None,
        });

    map.get(client_ip)
        .map(|e| e.locked_until.is_some())
        .unwrap_or(false)
}

/// Clear login failure state on successful login.
fn clear_login_failures(state: &DashboardState, client_ip: &str) {
    state.login_attempts.remove(client_ip);
}

// ── Login Handler ──────────────────────────────────────────

pub async fn login(
    Extension(state): Extension<std::sync::Arc<DashboardState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Response {
    let peer = req
        .extensions()
        .get::<axum::extract::connect_info::ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0.ip());
    let client_ip = extract_client_ip(req.headers(), peer);

    // 1. Rate-limit check.
    if let Some(remaining) = check_login_lockout(&state, &client_ip) {
        tracing::warn!(
            ip = %client_ip,
            remaining_secs = remaining.as_secs(),
            "Login blocked: too many attempts"
        );
        return json_error_response(
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            &format!("Too many login attempts. Try again in {} seconds.", remaining.as_secs()),
        );
    }

    // 2. Deserialize body.
    let LoginRequest { user_id, api_key, username, password, invite_code: _ } = match axum::body::to_bytes(req.into_body(), 4096).await
    {
        Ok(bytes) => match serde_json::from_slice::<LoginRequest>(&bytes) {
            Ok(req) => req,
            Err(e) => {
                tracing::warn!(ip = %client_ip, "Login: invalid JSON body: {}", e);
                return json_error_response(
                    axum::http::StatusCode::BAD_REQUEST,
                    "Invalid request body",
                );
            }
        },
        Err(e) => {
            tracing::warn!(ip = %client_ip, "Login: failed to read body: {}", e);
            return json_error_response(
                axum::http::StatusCode::BAD_REQUEST,
                "Failed to read request body",
            );
        }
    };

    let user_id = username.unwrap_or(user_id);

    // 3. Admin login: user_id == "admin" + constant-time comparison with master_key.
    if user_id == "admin" {
        let master_key = match &state.master_key {
            Some(k) => k,
            None => {
                return json_error_response(
                    axum::http::StatusCode::FORBIDDEN,
                    "Admin login disabled",
                );
            }
        };

        // Constant-time comparison.
        let equal = constant_time_eq(api_key.as_bytes(), master_key.as_bytes());
        if !equal {
            let _locked = record_login_failure(&state, &client_ip);
            tracing::warn!(ip = %client_ip, "Admin login: invalid credentials");
            return json_error_response(
                axum::http::StatusCode::UNAUTHORIZED,
                "Invalid credentials",
            );
        }

        clear_login_failures(&state, &client_ip);
        tracing::info!(ip = %client_ip, "Admin login success");
        return sign_and_respond(&state, "admin".to_string(), "admin".to_string(), String::new(), None, None);
    }

    if !api_key.is_empty() {
        return login_legacy_key(&state, &client_ip, &api_key);
    }
    let Some(password) = password else { return json_error_response(StatusCode::UNAUTHORIZED, "Username and password required"); };
    let pool = match &state.db_pool { Some(pool) => pool, None => return json_error_response(StatusCode::SERVICE_UNAVAILABLE, "Database not available") };
    let row = sqlx::query_as::<_, (uuid::Uuid, String, bool)>("SELECT id, password_hash, blocked FROM boom_account WHERE username = $1").bind(&user_id).fetch_optional(pool).await.ok().flatten();
    let Some((account_id, stored, blocked)) = row else { return json_error_response(StatusCode::UNAUTHORIZED, "Invalid credentials"); };
    if blocked || !verify_password(&stored, &password) { return json_error_response(StatusCode::UNAUTHORIZED, "Invalid credentials"); }
    let key_hash: String = sqlx::query_scalar("SELECT token FROM boom_verification_token WHERE account_id = $1 ORDER BY created_at LIMIT 1").bind(account_id).fetch_one(pool).await.unwrap_or_default();
    clear_login_failures(&state, &client_ip);
    sign_and_respond(&state, user_id, "user".to_string(), key_hash, None, Some(account_id))
}

fn login_legacy_key(state: &DashboardState, client_ip: &str, api_key: &str) -> Response {
    let _ = (state, client_ip, api_key);
    json_error_response(StatusCode::UNAUTHORIZED, "API key login is available through the LLM API; use username and password for the dashboard")
}

fn hash_password(salt: &str, password: &str) -> String {
    let mut hasher = Sha256::new(); hasher.update(salt.as_bytes()); hasher.update(password.as_bytes()); hex::encode(hasher.finalize())
}

fn verify_password(stored: &str, password: &str) -> bool {
    let Some((salt, digest)) = stored.split_once('$') else { return false; };
    constant_time_eq(hash_password(salt, password).as_bytes(), digest.as_bytes())
}

/* legacy API-key dashboard login removed from public flow */
/*
    let db_pool = match &state.db_pool {
        Some(pool) => pool,
        None => {
            tracing::error!("Login failed: no database pool configured");
            return json_error_response(
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                "Database not available",
            );
        }
    };

    // All keys are stored as SHA-256 of the entire raw key. This matches the
    // /v1 authenticate path (boom-auth) and the dashboard create-key path,
    // and is litellm-compatible. Prefix (if any) participates in the hash.
    let token_hash = hash_token(&api_key);

    let row_result: Result<Option<(Option<String>, Option<String>, Option<bool>)>, _> = sqlx::query_as(
        r#"SELECT user_id, key_alias, blocked FROM "boom_verification_token" WHERE token = $1"#,
    )
    .bind(&token_hash)
    .fetch_optional(db_pool)
    .await;

    let row = match row_result {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(
                ip = %client_ip,
                token_hash = &token_hash[..8.min(token_hash.len())],
                "Login DB query failed: {}",
                e
            );
            return json_error_response(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Database error during login",
            );
        }
    };

    let (uid, key_alias, blocked) = match row {
        Some((uid, alias, blk)) => (uid, alias, blk),
        None => {
            let _locked = record_login_failure(&state, &client_ip);
            tracing::warn!(
                ip = %client_ip,
                token_hash = &token_hash[..8.min(token_hash.len())],
                "Login: key not found in DB"
            );
            return json_error_response(
                axum::http::StatusCode::UNAUTHORIZED,
                "Invalid API key",
            );
        }
    };

    // Check blocked.
    if blocked.unwrap_or(false) {
        tracing::warn!(
            ip = %client_ip,
            token_hash = &token_hash[..8.min(token_hash.len())],
            "Login: key is blocked"
        );
        return json_error_response(
            axum::http::StatusCode::FORBIDDEN,
            "Key is blocked",
        );
    }

    clear_login_failures(&state, &client_ip);
    tracing::info!(
        ip = %client_ip,
        alias = ?key_alias,
        "User login success"
    );

    // Use key_alias as display name, fallback to user_id or "user".
    let display_name = key_alias
        .or(uid)
        .unwrap_or_else(|| "user".to_string());

    sign_and_respond(&state, display_name, "user".to_string(), token_hash, Some(api_key.clone()), None)
*/

fn sign_and_respond(
    state: &DashboardState,
    user_id: String,
    role: String,
    key_hash: String,
    api_key: Option<String>,
    account_id: Option<uuid::Uuid>,
) -> Response {
    let now = Utc::now().timestamp();
    let claims = DashboardClaims {
        sub: user_id.clone(),
        role: role.clone(),
        key_hash,
        account_id,
        exp: now + SESSION_DURATION_SECS,
        iat: now,
    };

    let token = match encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
    ) {
        Ok(t) => t,
        Err(_) => {
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to create session",
            )
                .into_response();
        }
    };

    let secure = if std::env::var("BOOM_PUBLIC_MODE").as_deref() == Ok("true") {
        "; Secure"
    } else {
        ""
    };
    let cookie = format!(
        "{}={}; HttpOnly; SameSite=Lax; Path=/dashboard; Max-Age={}{}",
        SESSION_COOKIE_NAME, token, SESSION_DURATION_SECS, secure
    );

    let body = Json(LoginResponse { role, user_id, api_key });

    ([(SET_COOKIE, cookie)], body).into_response()
}

// ── Logout Handler ─────────────────────────────────────────

pub async fn logout() -> Response {
    let secure = if std::env::var("BOOM_PUBLIC_MODE").as_deref() == Ok("true") {
        "; Secure"
    } else {
        ""
    };
    let cookie = format!(
        "{}=; HttpOnly; SameSite=Lax; Path=/dashboard; Max-Age=0{}",
        SESSION_COOKIE_NAME, secure
    );
    ([(SET_COOKIE, cookie)], axum::http::StatusCode::NO_CONTENT).into_response()
}

// ── Me Handler ─────────────────────────────────────────────

pub async fn me(session: DashboardSession) -> Json<MeResponse> {
    Json(MeResponse {
        user_id: session.claims.sub,
        role: session.claims.role,
    })
}

// ── Helpers ────────────────────────────────────────────────

fn json_error_response(status: axum::http::StatusCode, message: &str) -> Response {
    let mut resp = Json(serde_json::json!({ "error": message })).into_response();
    *resp.status_mut() = status;
    resp
}

pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}
