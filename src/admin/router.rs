//! Admin API 路由配置

use axum::{
    response::{Html, IntoResponse},
    routing::{delete, get, post},
    Router,
};

use super::{
    handlers::{
        add_credential, delete_all_disabled, delete_credential, get_all_credentials,
        get_credential_balance, reset_failure_count, set_credential_disabled,
        set_credential_priority,
    },
    middleware::AdminState,
};

/// Admin UI HTML 页面
const ADMIN_UI_HTML: &str = include_str!("admin_ui.html");

/// GET /ui - 返回 Admin UI 页面
async fn admin_ui() -> impl IntoResponse {
    Html(ADMIN_UI_HTML)
}

/// 创建 Admin API 路由
///
/// # 端点
/// - `GET /ui` - Admin UI 页面
/// - `GET /credentials` - 获取所有凭据状态
/// - `POST /credentials` - 添加新凭据
/// - `POST /credentials/:id/disabled` - 设置凭据禁用状态
/// - `POST /credentials/:id/priority` - 设置凭据优先级
/// - `POST /credentials/:id/reset` - 重置失败计数
/// - `GET /credentials/:id/balance` - 获取凭据余额
/// - `DELETE /credentials/:id` - 删除凭据
/// - `DELETE /credentials/disabled` - 批量删除所有禁用凭据
///
/// # 注意
/// 所有端点无需认证，可自由访问
pub fn create_admin_router(state: AdminState) -> Router {
    Router::new()
        .route("/ui", get(admin_ui))
        .route("/credentials", get(get_all_credentials).post(add_credential))
        .route("/credentials/disabled", delete(delete_all_disabled))
        .route("/credentials/{id}", delete(delete_credential))
        .route("/credentials/{id}/disabled", post(set_credential_disabled))
        .route("/credentials/{id}/priority", post(set_credential_priority))
        .route("/credentials/{id}/reset", post(reset_failure_count))
        .route("/credentials/{id}/balance", get(get_credential_balance))
        .with_state(state)
}
