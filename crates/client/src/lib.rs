//! A client library for Warg component registries.

#![deny(missing_docs)]

use crate::storage::PackageInfo;
use anyhow::{anyhow, Context, Result};
use reqwest::{Body, IntoUrl};
use std::{borrow::Cow, collections::HashMap, path::PathBuf, time::Duration};
use storage::{ContentStorage, PublishInfo, RegistryStorage};
use thiserror::Error;
use warg_api::v1::{
    fetch::{FetchError, FetchLogsRequest, FetchLogsResponse},
    package::{
        MissingContent, PackageError, PackageRecord, PackageRecordState, PublishRecordRequest,
        UploadEndpoint,
    },
    proof::{ConsistencyRequest, InclusionRequest},
};
use warg_crypto::{
    hash::{AnyHash, Hash, Sha256},
    signing,
};
use warg_protocol::{
    operator, package,
    registry::{LogId, LogLeaf, PackageId, RecordId, TimestampedCheckpoint},
    PublishedProtoEnvelope, SerdeEnvelope, Version, VersionReq,
};

pub mod api;
mod config;
mod registry_url;
pub mod storage;
pub use self::config::*;
pub use self::registry_url::RegistryUrl;

/// A client for a Warg registry.

/// A Warg registry client that uses the local file system to store
/// package logs and content.

/// A result of an attempt to lock client storage.
pub enum StorageLockResult<T> {
    /// The storage lock was acquired.
    Acquired(T),
    /// The storage lock was not acquired for the specified directory.
    NotAcquired(PathBuf),
}

/// Represents information about a downloaded package.
#[derive(Debug, Clone)]
pub struct PackageDownload {
    /// The package version that was downloaded.
    pub version: Version,
    /// The digest of the package contents.
    pub digest: AnyHash,
    /// The path to the downloaded package contents.
    pub path: PathBuf,
}

/// Represents an error returned by Warg registry clients.
#[derive(Debug, Error)]
pub enum ClientError {
    /// No default registry server URL is configured.
    #[error("no default registry server URL is configured")]
    NoDefaultUrl,

    /// The operator failed validation.
    #[error("operator failed validation: {inner}")]
    OperatorValidationFailed {
        /// The validation error.
        inner: operator::ValidationError,
    },

    /// The package already exists and cannot be initialized.
    #[error("package `{id}` already exists and cannot be initialized")]
    CannotInitializePackage {
        /// The identifier of the package that already exists.
        id: PackageId,
    },

    /// The package must be initialized before publishing.
    #[error("package `{id}` must be initialized before publishing")]
    MustInitializePackage {
        /// The name of the package that must be initialized.
        id: PackageId,
    },

    /// There is no publish operation in progress.
    #[error("there is no publish operation in progress")]
    NotPublishing,

    /// The package has no records to publish.
    #[error("package `{id}` has no records to publish")]
    NothingToPublish {
        /// The identifier of the package that has no publish operations.
        id: PackageId,
    },

    /// The package does not exist.
    #[error("package `{id}` does not exist")]
    PackageDoesNotExist {
        /// The identifier of the missing package.
        id: PackageId,
    },

    /// The package version does not exist.
    #[error("version `{version}` of package `{id}` does not exist")]
    PackageVersionDoesNotExist {
        /// The missing version of the package.
        version: Version,
        /// The identifier of the package with the missing version.
        id: PackageId,
    },

    /// The package failed validation.
    #[error("package `{id}` failed validation: {inner}")]
    PackageValidationFailed {
        /// The identifier of the package that failed validation.
        id: PackageId,
        /// The validation error.
        inner: package::ValidationError,
    },

    /// Content was not found during a publish operation.
    #[error("content with digest `{digest}` was not found in client storage")]
    ContentNotFound {
        /// The digest of the missing content.
        digest: AnyHash,
    },

    /// The package log is empty and cannot be validated.
    #[error("package log is empty and cannot be validated")]
    PackageLogEmpty {
        /// The identifier of the package with an empty package log.
        id: PackageId,
    },

    /// A publish operation was rejected.
    #[error("the publishing of package `{id}` was rejected due to: {reason}")]
    PublishRejected {
        /// The identifier of the package that was rejected.
        id: PackageId,
        /// The record identifier for the record that was rejected.
        record_id: RecordId,
        /// The reason it was rejected.
        reason: String,
    },

    /// The package is still missing content.
    #[error("the package is still missing content after all content was uploaded")]
    PackageMissingContent,

    /// An error occurred during an API operation.
    #[error(transparent)]
    Api(#[from] api::ClientError),

    /// An error occurred while performing a client operation.
    #[error("{0:?}")]
    Other(#[from] anyhow::Error),
}

impl ClientError {
    fn translate_log_not_found(
        e: api::ClientError,
        lookup: impl Fn(&LogId) -> Option<PackageId>,
    ) -> Self {
        match &e {
            api::ClientError::Fetch(FetchError::LogNotFound(id))
            | api::ClientError::Package(PackageError::LogNotFound(id)) => {
                if let Some(id) = lookup(id) {
                    return Self::PackageDoesNotExist { id };
                }
            }
            _ => {}
        }

        Self::Api(e)
    }
}

/// Represents the result of a client operation.
pub type ClientResult<T> = Result<T, ClientError>;
