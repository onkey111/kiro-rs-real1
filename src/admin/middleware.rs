//! Admin API 中间件

use std::sync::Arc;

use super::service::AdminService;

/// Admin API 共享状态
#[derive(Clone)]
pub struct AdminState {
    /// Admin 服务
    pub service: Arc<AdminService>,
}

impl AdminState {
    pub fn new(service: AdminService) -> Self {
        Self {
            service: Arc::new(service),
        }
    }
}
