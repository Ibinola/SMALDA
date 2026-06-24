use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use futures::future::join_all;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::{map_validation_error, AppState, ValidationErrorResponse};
use crate::hash_validator::HashValidator;

/// A single revocation item within a batch request.
#[derive(Debug, Deserialize, Clone)]
pub struct RevokeRequest {
    pub document_hash: String,
    pub reason: String,
    pub revoked_by: String,
}

/// Per-item result returned in the batch response.
#[derive(Debug, Serialize)]
pub struct BatchRevokeItem {
    pub document_hash: String,
    pub success: bool,
    pub tx_hash: Option<String>,
    pub error: Option<String>,
}

/// Top-level response for POST /revoke/batch.
#[derive(Debug, Serialize)]
pub struct BatchRevokeResponse {
    pub results: Vec<BatchRevokeItem>,
}

/// POST /revoke/batch — revoke up to 20 documents concurrently.
///
/// - Returns 400 if the array is empty or exceeds 20 items.
/// - Processes all valid revocations concurrently via `join_all`.
/// - Partial success is allowed; a failed item does not abort others.
/// - Duplicate / already-revoked hashes are reported as per-item errors.
pub async fn batch_revoke_documents(
    State(state): State<AppState>,
    Json(requests): Json<Vec<RevokeRequest>>,
) -> Response {
    if requests.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ValidationErrorResponse {
                error: "request array cannot be empty".to_string(),
            }),
        )
            .into_response();
    }

    if requests.len() > 20 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ValidationErrorResponse {
                error: "batch size exceeds maximum of 20 items".to_string(),
            }),
        )
            .into_response();
    }

    info!("Batch revoking {} documents", requests.len());
    state.metrics.increment_request_count();

    let futures: Vec<_> = requests
        .into_iter()
        .map(|req| {
            let state = state.clone();
            async move { revoke_single(&state, req).await }
        })
        .collect();

    let results = join_all(futures).await;

    Json(BatchRevokeResponse { results }).into_response()
}

/// Revoke a single document; returns a `BatchRevokeItem` for every outcome.
async fn revoke_single(state: &AppState, req: RevokeRequest) -> BatchRevokeItem {
    let normalized = HashValidator::normalize(&req.document_hash);

    // Validate hash format
    if let Err(err) = HashValidator::validate_sha256(&normalized) {
        let (_, body) = map_validation_error(err);
        return BatchRevokeItem {
            document_hash: req.document_hash,
            success: false,
            tx_hash: None,
            error: Some(body.error),
        };
    }

    // Check for duplicate / already-revoked via cache
    let revoked_key = format!("revoked:{}", normalized);
    match state.cache.get::<bool>(&revoked_key).await {
        Ok(Some(true)) => {
            return BatchRevokeItem {
                document_hash: normalized,
                success: false,
                tx_hash: None,
                error: Some("document already revoked".to_string()),
            };
        }
        Ok(_) => {}
        Err(e) => {
            warn!("Cache error checking revocation status: {}", e);
        }
    }

    // Anchor revocation on Stellar (reuse anchor_transfer as a generic memo anchor)
    let memo = format!("REVOKE:{}", &normalized[..19.min(normalized.len())]);
    match state.stellar.anchor_transfer(&normalized, &memo).await {
        Ok(()) => {
            // Mark as revoked in cache (permanent)
            if let Err(e) = state.cache.set(&revoked_key, &true, u64::MAX / 2).await {
                warn!("Failed to cache revocation status: {}", e);
            }

            // Generate a deterministic tx_hash placeholder from the normalized hash
            let tx_hash = format!("0x{}", &normalized[..16]);

            BatchRevokeItem {
                document_hash: normalized,
                success: true,
                tx_hash: Some(tx_hash),
                error: None,
            }
        }
        Err(e) => {
            warn!("Stellar revocation failed for {}: {}", normalized, e);
            state.metrics.increment_error_count();
            BatchRevokeItem {
                document_hash: normalized,
                success: false,
                tx_hash: None,
                error: Some(format!("stellar anchor failed: {}", e)),
            }
        }
    }
}
