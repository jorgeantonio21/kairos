use std::{convert::Infallible, net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    Router,
    extract::State,
    http::{HeaderValue, header},
    response::{Html, IntoResponse, Json, Response, Sse, sse},
    routing::get,
};
use tokio_stream::Stream;

use crate::{DashboardMetrics, DashboardSnapshot};

const INDEX_HTML: &str = include_str!("static/index.html");
const APP_JS: &str = include_str!("static/app.js");
const STYLE_CSS: &str = include_str!("static/style.css");

/// Serves the main dashboard page.
async fn index_handler() -> Html<&'static str> {
    Html(INDEX_HTML)
}

/// Serves static files (app.js, style.css) embedded at compile time.
async fn static_handler(axum::extract::Path(file): axum::extract::Path<String>) -> Response {
    match file.as_str() {
        "app.js" => {
            let mut resp = APP_JS.into_response();
            resp.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/javascript; charset=utf-8"),
            );
            resp
        }
        "style.css" => {
            let mut resp = STYLE_CSS.into_response();
            resp.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/css; charset=utf-8"),
            );
            resp
        }
        _ => axum::http::StatusCode::NOT_FOUND.into_response(),
    }
}

/// SSE endpoint: each client gets an independent stream that diffs snapshots every 100ms.
async fn sse_handler(
    State(dashboard): State<Arc<DashboardMetrics>>,
) -> Sse<impl Stream<Item = Result<sse::Event, Infallible>>> {
    let stream = async_stream::stream! {
        let mut prev = DashboardSnapshot::default();
        // Pre-fill prev.views with the right number of slots
        prev.views.resize_with(dashboard.views.len(), Default::default);

        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let current = DashboardSnapshot::from_metrics(&dashboard);
            for event in current.diff(&prev) {
                if let Ok(json) = serde_json::to_string(&event) {
                    yield Ok(sse::Event::default().data(json));
                }
            }
            prev = current;
        }
    };
    Sse::new(stream).keep_alive(sse::KeepAlive::default())
}

/// Full JSON snapshot of all active view slots.
async fn state_handler(State(dashboard): State<Arc<DashboardMetrics>>) -> Json<DashboardSnapshot> {
    Json(DashboardSnapshot::from_metrics(&dashboard))
}

/// Health check returning current view, finalized view.
async fn health_handler(State(dashboard): State<Arc<DashboardMetrics>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "current_view": dashboard.current_view.load(std::sync::atomic::Ordering::Relaxed),
        "finalized_view": dashboard.finalized_view.load(std::sync::atomic::Ordering::Relaxed),
        "node_n": dashboard.node_n.load(std::sync::atomic::Ordering::Relaxed),
        "node_f": dashboard.node_f.load(std::sync::atomic::Ordering::Relaxed),
    }))
}

/// Starts the visualizer axum server. Blocks until the server shuts down.
///
/// Intended to be called from a dedicated thread with its own single-threaded
/// tokio runtime (same pattern as the gRPC server in `node/src/node.rs`).
pub async fn run_server(dashboard: Arc<DashboardMetrics>, addr: SocketAddr) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/", get(index_handler))
        .route("/static/{file}", get(static_handler))
        .route("/api/events", get(sse_handler))
        .route("/api/state", get(state_handler))
        .route("/api/health", get(health_handler))
        .with_state(dashboard);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
