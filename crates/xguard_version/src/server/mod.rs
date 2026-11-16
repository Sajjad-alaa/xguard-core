//! Server-side middleware for adding XGuard version information to HTTP responses (either plain HTTP or gRPC).
//!
//! This module provides a tower-based middleware layer that automatically adds version
//! and system information headers to all HTTP responses. It can be used both with tonic and axum.
//!
//! The middleware is designed to
//! work with tonic's interceptor system and maintains compatibility with both regular
//! and intercepted services.
//!
//! # Headers Added
//!
//! - `xguard-version`: The semantic version of the XGuard component
//! - `xguard-system`: System information including OS type, version, and architecture
//!
//! # Usage
//!
//! ```
//! use tower::ServiceBuilder;
//! use xguard_version::server::XGuardVersionLayer;
//! use semver::Version;
//!
//! let my_grpc_service = ServiceBuilder::new();
//! let version = Version::parse("1.0.0").unwrap();
//! let version_layer = XGuardVersionLayer::new(version);
//! let service = ServiceBuilder::new()
//!     .layer(version_layer)
//!     .service(my_grpc_service);
//! ```

use tower::Layer;

use crate::ComponentInfo;

pub mod grpc;
pub mod http;

/// A tower `Layer` that adds XGuard version and system information headers to HTTP responses.
///
/// This layer wraps any service and ensures that all responses include version metadata
/// in HTTP headers. The layer is designed to be composable with other tower layers and
/// maintains the original service's `NamedService` implementation for tonic compatibility.
///
/// # Fields
///
/// * `component_info` - Contains version and system information that will be added to response
///   headers.
#[derive(Clone)]
pub struct XGuardVersionLayer {
    component_info: ComponentInfo,
}

impl XGuardVersionLayer {
    /// Creates a new version layer with the specified version string.
    ///
    /// # Arguments
    ///
    /// * `version` - Semantic version of the component
    ///
    /// # Returns
    ///
    /// * `Ok(XGuardVersionLayer)` - A new layer instance
    /// * `Err(XGuardVersionError)` - If the version string cannot be parsed
    #[must_use]
    pub fn new(version: crate::Version) -> Self {
        Self {
            component_info: ComponentInfo::new(version),
        }
    }
}

impl<S> Layer<S> for XGuardVersionLayer {
    type Service = XGuardVersionService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        XGuardVersionService {
            inner,
            component_info: self.component_info.clone(),
        }
    }
}

/// A tower `Service` that wraps another service and adds version headers to responses.
///
/// This service is created by the `XGuardVersionLayer` and implements the actual
/// header injection logic. It maintains full compatibility with the wrapped service's
/// interface while adding the version metadata functionality.
///
/// # Type Parameters
///
/// * `S` - The inner service type being wrapped
///
/// # Fields
///
/// * `inner` - The wrapped service that handles the actual request processing
/// * `component_info` - Version and system information to be added to response headers
#[derive(Clone)]
pub struct XGuardVersionService<S> {
    inner: S,
    component_info: ComponentInfo,
}
