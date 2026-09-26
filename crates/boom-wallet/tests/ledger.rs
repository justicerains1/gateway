use boom_wallet::{balance, cancel, credit, migrate, reserve, settle, WalletError};

static MIGRATION_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn idempotent_credit_reservation_and_settlement() {
    let Ok(url) = std::env::var("BOOM_TEST_DATABASE_URL") else {
        return;
    };
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    {
        let _guard = MIGRATION_LOCK.lock().await;
        migrate(&pool).await.unwrap();
    }
    let account = uuid::Uuid::new_v4();
    let order = uuid::Uuid::new_v4().to_string();
    let request = uuid::Uuid::new_v4().to_string();

    assert_eq!(
        credit(&pool, account, 1000, &order)
            .await
            .unwrap()
            .available_fen,
        1000
    );
    assert_eq!(
        credit(&pool, account, 1000, &order)
            .await
            .unwrap()
            .available_fen,
        1000
    );
    assert!(matches!(
        credit(&pool, account, 2000, &order).await,
        Err(WalletError::Conflict)
    ));
    assert_eq!(
        reserve(&pool, account, 700, &request)
            .await
            .unwrap()
            .available_fen,
        300
    );
    assert_eq!(
        reserve(&pool, account, 700, &request)
            .await
            .unwrap()
            .reserved_fen,
        700
    );
    assert_eq!(
        settle(&pool, &request, 450).await.unwrap().available_fen,
        550
    );
    assert_eq!(
        settle(&pool, &request, 450).await.unwrap().available_fen,
        550
    );
    assert!(matches!(
        cancel(&pool, &request).await,
        Err(WalletError::Conflict)
    ));
    assert_eq!(balance(&pool, account).await.unwrap().reserved_fen, 0);
}

#[tokio::test]
async fn concurrent_reservations_cannot_overspend() {
    let Ok(url) = std::env::var("BOOM_TEST_DATABASE_URL") else {
        return;
    };
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    {
        let _guard = MIGRATION_LOCK.lock().await;
        migrate(&pool).await.unwrap();
    }
    let account = uuid::Uuid::new_v4();
    credit(&pool, account, 100, &uuid::Uuid::new_v4().to_string())
        .await
        .unwrap();
    let a = uuid::Uuid::new_v4().to_string();
    let b = uuid::Uuid::new_v4().to_string();
    let (first, second) = tokio::join!(
        reserve(&pool, account, 80, &a),
        reserve(&pool, account, 80, &b)
    );
    assert_eq!(first.is_ok() as u8 + second.is_ok() as u8, 1);
    assert_eq!(balance(&pool, account).await.unwrap().available_fen, 20);
    if first.is_ok() {
        cancel(&pool, &a).await.unwrap();
    } else {
        cancel(&pool, &b).await.unwrap();
    }
    assert_eq!(balance(&pool, account).await.unwrap().available_fen, 100);
}
