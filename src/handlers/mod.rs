use argon2::{
    Argon2, PasswordHash, PasswordVerifier,
    password_hash::{PasswordHasher, SaltString},
};
// use axum::headers::{Authorization, Bearer};
use axum::{Extension, Json, extract::Request, http::StatusCode};
use headers::Authorization;
use headers::authorization::Bearer;
use rand::rngs::OsRng;
use sqlx::PgPool;
use uuid::Uuid;
// use axum::http::Request;
use headers::HeaderMapExt;

use crate::auth::{Claims, create_jwt, verify_jwt};
use crate::models::{SigninRequest, SignupRequest, TokenResponse};

pub async fn signup(
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<SignupRequest>,
) -> &'static str {
    // Hash password
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(payload.password.as_bytes(), &salt)
        .unwrap()
        .to_string();

    // Insert into DB
    let _ = sqlx::query!(
        "INSERT INTO users (id, username, password_hash) VALUES ($1, $2, $3)",
        Uuid::new_v4(),
        payload.username,
        password_hash
    )
    .execute(&pool)
    .await
    .expect("Failed to insert user");

    "User created"
}

pub async fn signin(
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<SigninRequest>,
) -> Result<Json<TokenResponse>, (axum::http::StatusCode, &'static str)> {
    let row = sqlx::query!(
        "SELECT id, password_hash FROM users WHERE username = $1",
        payload.username
    )
    .fetch_optional(&pool)
    .await
    .map_err(|_| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "DB error"))?;

    let user = match row {
        Some(user) => user,
        None => return Err((axum::http::StatusCode::UNAUTHORIZED, "Invalid credentials")),
    };

    let parsed_hash = PasswordHash::new(&user.password_hash).unwrap();
    let verified = Argon2::default()
        .verify_password(payload.password.as_bytes(), &parsed_hash)
        .is_ok();

    if !verified {
        return Err((axum::http::StatusCode::UNAUTHORIZED, "Invalid credentials"));
    }

    let token = create_jwt(&user.id.to_string(), &payload.username);
    Ok(Json(TokenResponse { token }))
}

pub async fn validate_token(req: Request<axum::body::Body>) -> Result<Json<Claims>, StatusCode> {
    let headers = req.headers();
    let bearer = headers
        .typed_get::<Authorization<Bearer>>()
        .ok_or(StatusCode::FORBIDDEN)?;

    match verify_jwt(bearer.token()) {
        Ok(data) => Ok(Json(data.claims)),
        Err(_) => Err(StatusCode::FORBIDDEN),
    }
}
