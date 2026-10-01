//! Classifies service failures without using diagnostic text.

/// Keeps the failure category separate from its diagnostic context.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// The request does not meet the input contract.
    #[error(transparent)]
    InvalidInput(anyhow::Error),
    /// The requested resource does not exist.
    #[error(transparent)]
    NotFound(anyhow::Error),
    /// The request conflicts with an existing resource.
    #[error(transparent)]
    Conflict(anyhow::Error),
    /// An operation failed without a caller-correctable cause.
    #[error(transparent)]
    Internal(anyhow::Error),
}

impl From<anyhow::Error> for ServiceError {
    /// Preserves typed failures across storage and task boundaries that use anyhow.
    /// Treats unclassified failures as internal errors and keeps all context.
    fn from(error: anyhow::Error) -> Self {
        match error.chain().find_map(|cause| cause.downcast_ref::<Self>()) {
            Some(Self::InvalidInput(_)) => Self::InvalidInput(error),
            Some(Self::NotFound(_)) => Self::NotFound(error),
            Some(Self::Conflict(_)) => Self::Conflict(error),
            Some(Self::Internal(_)) | None => Self::Internal(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversion_preserves_category_and_diagnostic_context() {
        for original in [
            ServiceError::InvalidInput(anyhow::anyhow!("request rejected")),
            ServiceError::NotFound(anyhow::anyhow!("missing resource")),
            ServiceError::Conflict(anyhow::anyhow!("duplicate resource")),
            ServiceError::Internal(anyhow::anyhow!("storage failed")),
        ] {
            let category = std::mem::discriminant(&original);
            let error = anyhow::Error::new(original).context("operation failed");
            let diagnostic = format!("{error:#}");
            let converted = ServiceError::from(error);
            assert_eq!(std::mem::discriminant(&converted), category);
            assert_eq!(converted.to_string(), "operation failed");
            assert_eq!(format!("{:#}", anyhow::Error::new(converted)), diagnostic);
        }
    }

    #[test]
    fn unclassified_diagnostic_text_does_not_change_category() {
        let error = ServiceError::from(anyhow::anyhow!(
            "invalid configuration: resource not found or already exists"
        ));
        assert!(matches!(error, ServiceError::Internal(_)));
    }
}
