use crate::auth::{AdminSession, DashboardSession};
use crate::state::DashboardState;
use axum::{extract::Path, response::IntoResponse, Extension, Json};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct CreateInvitationRequest {
    pub code: String,
    pub max_uses: Option<i32>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

pub async fn create_invitation(
    _session: AdminSession,
    Extension(state): Extension<std::sync::Arc<DashboardState>>,
    Json(req): Json<CreateInvitationRequest>,
) -> impl IntoResponse {
    let Some(pool) = &state.db_pool else { return Json(json!({"error":"Database not available"})); };
    let uses = req.max_uses.unwrap_or(1).max(1);
    let result = sqlx::query("INSERT INTO boom_invitation(code,max_uses,expires_at) VALUES ($1,$2,$3)")
        .bind(req.code.trim()).bind(uses).bind(req.expires_at).execute(pool).await;
    match result { Ok(_) => Json(json!({"code": req.code, "max_uses": uses})), Err(e) => Json(json!({"error": e.to_string()})) }
}

#[derive(Debug, Deserialize)]
pub struct CreditRequest { pub amount_fen: i64, pub reference: Option<String> }

pub async fn credit_account(
    _session: AdminSession,
    Extension(state): Extension<std::sync::Arc<DashboardState>>,
    Path(account_id): Path<Uuid>,
    Json(req): Json<CreditRequest>,
) -> impl IntoResponse {
    let Some(pool) = &state.db_pool else { return Json(json!({"error":"Database not available"})); };
    let reference = req.reference.unwrap_or_else(|| format!("admin-credit:{}", Uuid::new_v4()));
    match boom_wallet::credit(pool, account_id, req.amount_fen, &reference).await {
        Ok(balance) => Json(json!({"account_id":account_id,"available_fen":balance.available_fen,"reserved_fen":balance.reserved_fen,"reference":reference})),
        Err(e) => Json(json!({"error":e.to_string()})),
    }
}

pub async fn account_balance(
    session: DashboardSession,
    Extension(state): Extension<std::sync::Arc<DashboardState>>,
) -> impl IntoResponse {
    let Some(account_id) = session.claims.account_id else { return Json(json!({"available_fen":0,"reserved_fen":0})); };
    let Some(pool) = &state.db_pool else { return Json(json!({"error":"Database not available"})); };
    match boom_wallet::balance(pool, account_id).await {
        Ok(balance) => Json(json!({"account_id":account_id,"available_fen":balance.available_fen,"reserved_fen":balance.reserved_fen})),
        Err(e) => Json(json!({"error":e.to_string()})),
    }
}
