use axum::{
    Json, Router,
    extract::Path,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    // Define your app
    let app = Router::new()
        .route("/", get(root))
        .route("/echo", post(echo))
        .route("/hello/:name", get(hello));

    // Bind to an address using TcpListener
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let listener = TcpListener::bind(addr).await.unwrap();

    // Use axum::serve with the listener
    axum::serve(listener, app).await.unwrap();
}

async fn root() -> &'static str {
    "Welcome to Axum!"
}

#[derive(Deserialize, Serialize)]
struct EchoData {
    message: String,
}

async fn echo(Json(payload): Json<EchoData>) -> Json<EchoData> {
    Json(EchoData {
        message: format!("Echo: {}", payload.message),
    })
}

async fn hello(Path(name): Path<String>) -> String {
    format!("Hello, {}!", name)
}
