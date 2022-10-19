use fastly::http::header::HeaderName;
use fastly::http::header::{CONTENT_LENGTH, CONTENT_TYPE};

/// This should match the name of your storage backend. See the the `Hosts` section of
/// the Fastly WASM service UI for more information.
pub(crate) const BACKEND_NAME: &str = "bucket_origin";

/// Allowlist of headers for responses to the client.
pub(crate) static ALLOWED_HEADERS: [HeaderName; 2] = [CONTENT_LENGTH, CONTENT_TYPE];

/// The name of the bucket to serve content from. By default, this is an example bucket on a mock endpoint.
pub(crate) const BUCKET_NAME: &str = "yara-rs-demo-bucket";

/// The host that the bucket is served on. This is used to make requests to the backend.
pub(crate) const BUCKET_HOST: &str = "storage.googleapis.com";
