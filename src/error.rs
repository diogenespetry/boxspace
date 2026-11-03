//! S3-style error type and its XML rendering.

use std::fmt::Display;

use axum::{body::Body, http::StatusCode, response::Response};

use crate::util::{esc, set_header, XML_DECL};

#[derive(Debug)]
pub struct S3Error {
    pub code: &'static str,
    pub message: String,
    pub status: StatusCode,
    pub resource: Option<String>,
    pub headers: Vec<(&'static str, String)>,
}

pub type Result<T, E = S3Error> = std::result::Result<T, E>;

impl S3Error {
    pub fn new(code: &'static str, status: u16, message: impl Into<String>) -> Self {
        S3Error {
            code,
            message: message.into(),
            status: StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            resource: None,
            headers: Vec::new(),
        }
    }

    pub fn resource(mut self, r: impl Into<String>) -> Self {
        self.resource = Some(r.into());
        self
    }

    pub fn header(mut self, k: &'static str, v: impl Into<String>) -> Self {
        self.headers.push((k, v.into()));
        self
    }

    pub fn to_response(&self, head: bool, request_id: &str) -> Response {
        let body = if head || self.status == StatusCode::NOT_MODIFIED {
            Body::empty()
        } else {
            let res = self
                .resource
                .as_ref()
                .map(|r| format!("<Resource>{}</Resource>", esc(r)))
                .unwrap_or_default();
            Body::from(format!(
                "{XML_DECL}<Error><Code>{}</Code><Message>{}</Message>{res}<RequestId>{request_id}</RequestId></Error>",
                self.code,
                esc(&self.message)
            ))
        };
        let mut resp = Response::new(body);
        *resp.status_mut() = self.status;
        let h = resp.headers_mut();
        if !head && self.status != StatusCode::NOT_MODIFIED {
            set_header(h, "content-type", "application/xml");
        }
        for (k, v) in &self.headers {
            set_header(h, k, v);
        }
        resp
    }

    // ---- common errors ----

    pub fn internal(e: impl Display) -> Self {
        tracing::error!("internal error: {e}");
        Self::new("InternalError", 500, "We encountered an internal error. Please try again.")
    }
    pub fn access_denied() -> Self {
        Self::new("AccessDenied", 403, "Access Denied.")
    }
    pub fn no_such_bucket(b: &str) -> Self {
        Self::new("NoSuchBucket", 404, "The specified bucket does not exist").resource(b)
    }
    pub fn no_such_key(k: &str) -> Self {
        Self::new("NoSuchKey", 404, "The specified key does not exist.").resource(k)
    }
    pub fn no_such_version() -> Self {
        Self::new("NoSuchVersion", 404, "The specified version does not exist.")
    }
    pub fn no_such_upload() -> Self {
        Self::new(
            "NoSuchUpload",
            404,
            "The specified multipart upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed.",
        )
    }
    pub fn invalid_argument(m: impl Into<String>) -> Self {
        Self::new("InvalidArgument", 400, m)
    }
    pub fn invalid_request(m: impl Into<String>) -> Self {
        Self::new("InvalidRequest", 400, m)
    }
    pub fn malformed_xml() -> Self {
        Self::new(
            "MalformedXML",
            400,
            "The XML you provided was not well-formed or did not validate against our published schema.",
        )
    }
    pub fn not_implemented(m: impl Into<String>) -> Self {
        Self::new("NotImplemented", 501, m)
    }
    pub fn method_not_allowed() -> Self {
        Self::new("MethodNotAllowed", 405, "The specified method is not allowed against this resource.")
    }
    pub fn precondition_failed() -> Self {
        Self::new("PreconditionFailed", 412, "At least one of the pre-conditions you specified did not hold")
    }
    pub fn not_modified() -> Self {
        Self::new("NotModified", 304, "Not Modified")
    }
    pub fn invalid_range() -> Self {
        Self::new("InvalidRange", 416, "The requested range is not satisfiable")
    }
    pub fn bad_digest(m: impl Into<String>) -> Self {
        Self::new("BadDigest", 400, m)
    }
    pub fn signature_mismatch() -> Self {
        Self::new(
            "SignatureDoesNotMatch",
            403,
            "The request signature we calculated does not match the signature you provided. Check your key and signing method.",
        )
    }
    pub fn incomplete_body() -> Self {
        Self::new("IncompleteBody", 400, "You did not provide the number of bytes specified by the Content-Length HTTP header.")
    }
}

impl From<std::io::Error> for S3Error {
    fn from(e: std::io::Error) -> Self {
        Self::internal(e)
    }
}
impl From<serde_json::Error> for S3Error {
    fn from(e: serde_json::Error) -> Self {
        Self::internal(e)
    }
}

macro_rules! redb_from {
    ($($t:ty),*) => {$(
        impl From<$t> for S3Error {
            fn from(e: $t) -> Self { Self::internal(e) }
        }
    )*};
}
redb_from!(
    redb::Error,
    redb::DatabaseError,
    redb::TransactionError,
    redb::TableError,
    redb::StorageError,
    redb::CommitError
);
