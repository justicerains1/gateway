use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Balance {
    pub available_fen: i64,
    pub reserved_fen: i64,
}

struct BalanceDelta {
    available_fen: i64,
    reserved_fen: i64,
    spent_fen: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("amount must be positive")]
    InvalidAmount,
    #[error("wallet balance is insufficient")]
    InsufficientFunds,
    #[error("idempotency key conflicts with another operation")]
    Conflict,
    #[error("reservation not found")]
    HoldNotFound,
    #[error("settlement exceeds the reserved amount")]
    ExceedsReservation,
    #[error("balance would overflow")]
    Overflow,
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

pub async fn migrate(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::raw_sql(
        r#"
        CREATE TABLE IF NOT EXISTS boom_wallet (
            account_id UUID PRIMARY KEY,
            available_fen BIGINT NOT NULL DEFAULT 0 CHECK (available_fen >= 0),
            reserved_fen BIGINT NOT NULL DEFAULT 0 CHECK (reserved_fen >= 0),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS boom_wallet_hold (
            request_id TEXT PRIMARY KEY,
            account_id UUID NOT NULL REFERENCES boom_wallet(account_id),
            reserved_fen BIGINT NOT NULL CHECK (reserved_fen > 0),
            settled_fen BIGINT,
            status TEXT NOT NULL CHECK (status IN ('reserved', 'settled', 'cancelled')),
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS boom_wallet_event (
            id BIGSERIAL PRIMARY KEY,
            account_id UUID NOT NULL REFERENCES boom_wallet(account_id),
            reference TEXT NOT NULL UNIQUE,
            kind TEXT NOT NULL CHECK (kind IN ('credit', 'reserve', 'settle', 'cancel')),
            available_delta_fen BIGINT NOT NULL,
            reserved_delta_fen BIGINT NOT NULL,
            spent_fen BIGINT NOT NULL DEFAULT 0 CHECK (spent_fen >= 0),
            available_after_fen BIGINT NOT NULL,
            reserved_after_fen BIGINT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_boom_wallet_event_account_id
            ON boom_wallet_event(account_id, id DESC);
        "#,
    )
    .execute(pool)
    .await?;
    Ok(())
}

async fn lock_wallet(
    tx: &mut Transaction<'_, Postgres>,
    account_id: Uuid,
) -> Result<Balance, WalletError> {
    sqlx::query("INSERT INTO boom_wallet(account_id) VALUES ($1) ON CONFLICT DO NOTHING")
        .bind(account_id)
        .execute(&mut **tx)
        .await?;
    let (available_fen, reserved_fen): (i64, i64) = sqlx::query_as(
        "SELECT available_fen, reserved_fen FROM boom_wallet WHERE account_id = $1 FOR UPDATE",
    )
    .bind(account_id)
    .fetch_one(&mut **tx)
    .await?;
    Ok(Balance {
        available_fen,
        reserved_fen,
    })
}

async fn write_balance(
    tx: &mut Transaction<'_, Postgres>,
    account_id: Uuid,
    balance: Balance,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE boom_wallet SET available_fen = $2, reserved_fen = $3, updated_at = NOW() WHERE account_id = $1",
    )
    .bind(account_id)
    .bind(balance.available_fen)
    .bind(balance.reserved_fen)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn event(
    tx: &mut Transaction<'_, Postgres>,
    account_id: Uuid,
    reference: &str,
    kind: &str,
    delta: BalanceDelta,
    after: Balance,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO boom_wallet_event(account_id, reference, kind, available_delta_fen, reserved_delta_fen, spent_fen, available_after_fen, reserved_after_fen) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(account_id)
    .bind(reference)
    .bind(kind)
    .bind(delta.available_fen)
    .bind(delta.reserved_fen)
    .bind(delta.spent_fen)
    .bind(after.available_fen)
    .bind(after.reserved_fen)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub async fn balance(pool: &PgPool, account_id: Uuid) -> Result<Balance, WalletError> {
    let row: Option<(i64, i64)> =
        sqlx::query_as("SELECT available_fen, reserved_fen FROM boom_wallet WHERE account_id = $1")
            .bind(account_id)
            .fetch_optional(pool)
            .await?;
    Ok(row.map_or(
        Balance {
            available_fen: 0,
            reserved_fen: 0,
        },
        |(available_fen, reserved_fen)| Balance {
            available_fen,
            reserved_fen,
        },
    ))
}

pub async fn credit(
    pool: &PgPool,
    account_id: Uuid,
    amount_fen: i64,
    reference: &str,
) -> Result<Balance, WalletError> {
    if amount_fen <= 0 || reference.is_empty() {
        return Err(WalletError::InvalidAmount);
    }
    let mut tx = pool.begin().await?;
    let before = lock_wallet(&mut tx, account_id).await?;
    let prior: Option<(Uuid, i64, String)> = sqlx::query_as(
        "SELECT account_id, available_delta_fen, kind FROM boom_wallet_event WHERE reference = $1",
    )
    .bind(reference)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some((owner, amount, kind)) = prior {
        if owner != account_id || amount != amount_fen || kind != "credit" {
            return Err(WalletError::Conflict);
        }
        tx.commit().await?;
        return Ok(before);
    }
    let after = Balance {
        available_fen: before
            .available_fen
            .checked_add(amount_fen)
            .ok_or(WalletError::Overflow)?,
        reserved_fen: before.reserved_fen,
    };
    write_balance(&mut tx, account_id, after).await?;
    event(
        &mut tx,
        account_id,
        reference,
        "credit",
        BalanceDelta {
            available_fen: amount_fen,
            reserved_fen: 0,
            spent_fen: 0,
        },
        after,
    )
    .await?;
    tx.commit().await?;
    Ok(after)
}

pub async fn reserve(
    pool: &PgPool,
    account_id: Uuid,
    amount_fen: i64,
    request_id: &str,
) -> Result<Balance, WalletError> {
    if amount_fen <= 0 || request_id.is_empty() {
        return Err(WalletError::InvalidAmount);
    }
    let mut tx = pool.begin().await?;
    let before = lock_wallet(&mut tx, account_id).await?;
    let prior: Option<(Uuid, i64)> = sqlx::query_as(
        "SELECT account_id, reserved_fen FROM boom_wallet_hold WHERE request_id = $1",
    )
    .bind(request_id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some((owner, amount)) = prior {
        if owner != account_id || amount != amount_fen {
            return Err(WalletError::Conflict);
        }
        tx.commit().await?;
        return Ok(before);
    }
    if before.available_fen < amount_fen {
        return Err(WalletError::InsufficientFunds);
    }
    let after = Balance {
        available_fen: before.available_fen - amount_fen,
        reserved_fen: before
            .reserved_fen
            .checked_add(amount_fen)
            .ok_or(WalletError::Overflow)?,
    };
    write_balance(&mut tx, account_id, after).await?;
    sqlx::query("INSERT INTO boom_wallet_hold(request_id, account_id, reserved_fen, status) VALUES ($1,$2,$3,'reserved')")
        .bind(request_id)
        .bind(account_id)
        .bind(amount_fen)
        .execute(&mut *tx)
        .await?;
    event(
        &mut tx,
        account_id,
        &format!("reserve:{request_id}"),
        "reserve",
        BalanceDelta {
            available_fen: -amount_fen,
            reserved_fen: amount_fen,
            spent_fen: 0,
        },
        after,
    )
    .await?;
    tx.commit().await?;
    Ok(after)
}

pub async fn settle(
    pool: &PgPool,
    request_id: &str,
    actual_fen: i64,
) -> Result<Balance, WalletError> {
    if actual_fen < 0 {
        return Err(WalletError::InvalidAmount);
    }
    let mut tx = pool.begin().await?;
    let owner: Option<(Uuid,)> =
        sqlx::query_as("SELECT account_id FROM boom_wallet_hold WHERE request_id = $1")
            .bind(request_id)
            .fetch_optional(&mut *tx)
            .await?;
    let account_id = owner.ok_or(WalletError::HoldNotFound)?.0;
    let before = lock_wallet(&mut tx, account_id).await?;
    let (reserved_fen, status, settled_fen): (i64, String, Option<i64>) = sqlx::query_as(
        "SELECT reserved_fen, status, settled_fen FROM boom_wallet_hold WHERE request_id = $1 FOR UPDATE",
    )
    .bind(request_id)
    .fetch_one(&mut *tx)
    .await?;
    if status == "settled" && settled_fen == Some(actual_fen) {
        tx.commit().await?;
        return Ok(before);
    }
    if status != "reserved" {
        return Err(WalletError::Conflict);
    }
    if actual_fen > reserved_fen {
        return Err(WalletError::ExceedsReservation);
    }
    let released = reserved_fen - actual_fen;
    let after = Balance {
        available_fen: before
            .available_fen
            .checked_add(released)
            .ok_or(WalletError::Overflow)?,
        reserved_fen: before.reserved_fen - reserved_fen,
    };
    write_balance(&mut tx, account_id, after).await?;
    sqlx::query("UPDATE boom_wallet_hold SET status = 'settled', settled_fen = $2, updated_at = NOW() WHERE request_id = $1")
        .bind(request_id)
        .bind(actual_fen)
        .execute(&mut *tx)
        .await?;
    event(
        &mut tx,
        account_id,
        &format!("settle:{request_id}"),
        "settle",
        BalanceDelta {
            available_fen: released,
            reserved_fen: -reserved_fen,
            spent_fen: actual_fen,
        },
        after,
    )
    .await?;
    tx.commit().await?;
    Ok(after)
}

pub async fn cancel(pool: &PgPool, request_id: &str) -> Result<Balance, WalletError> {
    let mut tx = pool.begin().await?;
    let owner: Option<(Uuid,)> =
        sqlx::query_as("SELECT account_id FROM boom_wallet_hold WHERE request_id = $1")
            .bind(request_id)
            .fetch_optional(&mut *tx)
            .await?;
    let account_id = owner.ok_or(WalletError::HoldNotFound)?.0;
    let before = lock_wallet(&mut tx, account_id).await?;
    let (reserved_fen, status): (i64, String) = sqlx::query_as(
        "SELECT reserved_fen, status FROM boom_wallet_hold WHERE request_id = $1 FOR UPDATE",
    )
    .bind(request_id)
    .fetch_one(&mut *tx)
    .await?;
    if status == "cancelled" {
        tx.commit().await?;
        return Ok(before);
    }
    if status != "reserved" {
        return Err(WalletError::Conflict);
    }
    let after = Balance {
        available_fen: before
            .available_fen
            .checked_add(reserved_fen)
            .ok_or(WalletError::Overflow)?,
        reserved_fen: before.reserved_fen - reserved_fen,
    };
    write_balance(&mut tx, account_id, after).await?;
    sqlx::query("UPDATE boom_wallet_hold SET status = 'cancelled', updated_at = NOW() WHERE request_id = $1")
        .bind(request_id)
        .execute(&mut *tx)
        .await?;
    event(
        &mut tx,
        account_id,
        &format!("cancel:{request_id}"),
        "cancel",
        BalanceDelta {
            available_fen: reserved_fen,
            reserved_fen: -reserved_fen,
            spent_fen: 0,
        },
        after,
    )
    .await?;
    tx.commit().await?;
    Ok(after)
}
