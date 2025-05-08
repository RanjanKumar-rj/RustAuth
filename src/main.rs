use axum::{
    Extension, Router,
    routing::{get, post},
};
use std::net::SocketAddr;
use tokio::net::TcpListener;

mod auth;
mod db;
mod handlers;
mod models;

use db::connect_to_db;
use handlers::{signin, signup, validate_token};

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    let pool = connect_to_db().await;

    let app = Router::new()
        .route("/signup", post(signup))
        .route("/signin", post(signin))
        .route("/validate", get(validate_token))
        .layer(Extension(pool)); // Pass DB pool

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let listener = TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
