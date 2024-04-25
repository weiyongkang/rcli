use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Router,
};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tower_http::services::ServeDir;
use tracing::info;

#[derive(Debug)]
struct HttpServerState {
    path: PathBuf,
}

pub async fn process_http_server(path: PathBuf, port: u16) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Serving {:?} on port {}", path, port);

    let state = HttpServerState { path: path.clone() };
    let dir_service = ServeDir::new(path)
        .append_index_html_on_directories(true)
        .precompressed_gzip()
        .precompressed_br()
        .precompressed_deflate()
        .precompressed_zstd();

    let router = Router::new()
        .route("/*path", get(file_handler))
        .nest_service("/tower", dir_service)
        .with_state(Arc::new(state));

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;

    Ok(())
}

// todo 返回数据是string，因为会直接读取到string，所以会有问题，到时候调整成 读取后直接写入输出流
async fn file_handler(
    State(state): State<Arc<HttpServerState>>,
    Path(path): Path<String>,
) -> impl IntoResponse {
    let p: PathBuf = std::path::Path::new(&state.path).join(path);

    if !p.exists() {
        (
            StatusCode::NOT_FOUND,
            [("content-type", "text/plain")],
            format!("file {} is not found !!!", p.display()).into(),
        )
    } else if p.is_dir() {
        // get dir file list build html
        let mut html = String::new();
        html.push_str("<html>");
        html.push_str(
            format!(
                "<head><title>{}</title></head>",
                p.file_name().unwrap().to_os_string().into_string().unwrap()
            )
            .as_str(),
        );
        html.push_str("<body>");
        html.push_str("<ul>");
        for file in p.read_dir().unwrap() {
            let file = file.unwrap();
            // let path = file.path();
            // let path = path.strip_prefix(&state.path).unwrap();
            let path = file.file_name().into_string().unwrap();
            html.push_str(
                format!(
                    "<li><a href=\"{}\">{}</a></li>",
                    path,
                    file.file_name().to_str().unwrap()
                )
                .as_str(),
            );
        }
        html.push_str("</ul>");
        html.push_str("</body>");
        html.push_str("</html>");
        (
            StatusCode::OK,
            [("content-type", "text/html; charset=utf-8")],
            html.into(),
        )
    } else {
        // get file content
        match tokio::fs::read(p).await {
            Ok(content) => (
                StatusCode::OK,
                [("content-type", "application/download")],
                content,
            ),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                [("content-type", "text/plain")],
                e.to_string().into(),
            ),
        }
    }
}
