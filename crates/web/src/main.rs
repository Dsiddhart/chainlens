use axum::{
    async_trait,
    extract::{FromRequest, Json, Request},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};

#[tokio::main]
async fn main() {
    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(3000);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    let app = Router::new()
        .route("/", get(serve_index))
        .route("/api/health", get(health_check))
        .route("/api/analyze", post(analyze_transaction))
        .layer(CorsLayer::new().allow_origin(Any));

    println!("http://127.0.0.1:{}", port);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true }))
}


struct ValidatedJson<T>(T);

#[async_trait]
impl<T, S> FromRequest<S> for ValidatedJson<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(ValidatedJson(value)),
            Err(err) => {
                let error = serde_json::json!({
                    "ok": false,
                    "error": {
                        "code": "INVALID_REQUEST",
                        "message": err.to_string()
                    }
                });
                Err(Json(error).into_response())
            }
        }
    }
}

async fn analyze_transaction(
    ValidatedJson(payload): ValidatedJson<AnalyzeRequest>,
) -> Response {
    match btc_core::transaction::parse_raw_transaction(&payload.raw_tx, &payload.prevouts) {
        Ok(transaction) => Json(transaction).into_response(),
        Err(err) => {
            let error = serde_json::json!({
                "ok": false,
                "error": {
                    "code": "PARSE_ERROR",
                    "message": format!("{:?}", err)
                }
            });
            Json(error).into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
struct AnalyzeRequest {
    raw_tx: String,
    prevouts: Vec<serde_json::Value>,
}

async fn serve_index() -> Html<&'static str> {
    Html(include_str!("index.html"))
}