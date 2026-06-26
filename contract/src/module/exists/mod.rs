use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use tracing::{info, warn};

use crate::hash_validator::HashValidator;
use crate::{map_validation_error, AppState, VerifyResponse};

/// Minimal response for the document existence check endpoint.
#[derive(Debug, Serialize)]
pub struct ExistsResponse {
    pub exists: bool,
    pub cached: bool,
}

/// GET /exists/:hash — lightweight existence check.
///
/// Checks Redis first (using the same key as the verify endpoint).
/// Falls back to a Stellar lookup on cache miss.
/// Positive results (exists=true) are cached with no TTL (permanent existence).
/// Negative results (exists=false) are cached with a 60-second TTL.
pub async fn check_document_exists(
    State(state): State<AppState>,
    Path(hash): Path<String>,
) -> Response {
    let normalized = HashValidator::normalize(&hash);
    if let Err(err) = HashValidator::validate_sha256(&normalized) {
        let (status, body) = map_validation_error(err);
        return (status, Json(body)).into_response();
    }

    info!("Existence check for hash: {}", normalized);

    // Check cache — verify endpoint stores VerifyResponse under the bare hash key.
    match state.cache.get::<VerifyResponse>(&normalized).await {
        Ok(Some(cached)) => {
            info!("Cache hit for existence check: {}", normalized);
            state.metrics.increment_cache_hits();
            return Json(ExistsResponse {
                exists: cached.verified,
                cached: true,
            })
            .into_response();
        }
        Ok(None) => {}
        Err(e) => {
            warn!("Cache error on existence check: {}", e);
        }
    }

    state.metrics.increment_cache_misses();

    // Fall back to Stellar
    let result = match state.stellar.verify_hash(&normalized).await {
        Ok(r) => r,
        Err(e) => {
            warn!("Stellar query failed during existence check: {}", e);
            state.metrics.increment_error_count();
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // Positive → permanent cache; negative → 60-second TTL
    let ttl: u64 = if result.verified { u64::MAX / 2 } else { 60 };
    let cache_entry = VerifyResponse {
        verified: result.verified,
        transaction_id: result.transaction_id,
        timestamp: result.timestamp,
        cached: false,
    };
    if let Err(e) = state.cache.set(&normalized, &cache_entry, ttl).await {
        warn!("Failed to cache existence result: {}", e);
    }

    Json(ExistsResponse {
        exists: result.verified,
        cached: false,
    })
    .into_response()
}
