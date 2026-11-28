//! Inbox Doctor jobs, mailbox downloads and OAuth (port of
//! `backend/app/doctor/router.py`; services in the `mail-doctor` crate,
//! whose [`JobRunner`] holds the route-level operations so these handlers
//! only parse input, run the blocking work and shape the response).
//!
//! `JobOut` = `{id, filename, file_size, status, progress, stage, log,
//! error_message, created_at, completed_at, output_files[], source_kind,
//! account_email, days, downloaded_messages, total_messages,
//! snapshot_available, snapshot_at, run_kind, scheduled_for, window_start,
//! window_end}`. "capacity" = `runner.ensure_capacity()` → 429 `{"detail": str}`.
//!
//! | Method | Path | Params / body | Success | Errors |
//! |--------|------|---------------|---------|--------|
//! | POST   | `/api/jobs` | multipart `files` (1..=1000; extensions .eml/.zip/.mbox/.json; at least one .eml/.zip/.mbox; staged within `max_upload_bytes`); size layer `RequestSizeLimitLayer::doctor_upload(max_upload_bytes)` | **201** `JobOut` | 413 `"Request exceeds maximum allowed size"`, 429 capacity, 400 `"Upload between 1 and 1000 files"`, 400 `"Unsupported file type: {name}. Accepted: .eml, .zip, .mbox, .json"`, 400 `"Upload must include at least one .eml, .zip, or .mbox file"`, 400 staging error text, 422 |
//! | POST   | `/api/jobs/paste` | JSON `PasteJobIn` `{content: str(1..=200 MiB), filename?: str(<=1000)|null}`; same size layer | **201** `JobOut` | 413, 429, 400 `"Pasted source exceeds maximum allowed size"`, 422 |
//! | GET    | `/api/mail/providers` | query `email: str(max 320)=""` | 200 `{"provider", "imap_server", "imap_port", "use_ssl", "oauth_configured": bool|null, "oauth_callback_url": str|null, "known_domains": [..]}` | 422 |
//! | POST   | `/api/mail/jobs/account` | JSON `AccountJobIn` `{account: str(3..=320), days: int(1..=3650)=7}` | **201** `JobOut` (auth from the unlocked session) | 401 `password_required`, 400 POP3 account, 429, 422 |
//! | POST   | `/api/mail/jobs` | JSON `MailCredentialsIn` `{email: str(3..=320), password: str(1..=4096), days=7 (1..=3650), imap_server?: str(<=253), imap_port?: int(1..=65535), use_ssl?: bool, use_app_password: bool=false, incoming_protocol?: ^(SSL/TLS|STARTTLS|NONE)$}` | **201** `JobOut` | 400 `"Enter a valid email address"`, 400 `"Microsoft accounts must use the permission-based OAuth button."`, 400 `"Google accounts must use OAuth or explicitly choose the app-password fallback."`, 400 `"A Google app password must contain 16 characters (letters or digits)."`, 429, 422 |
//! | POST   | `/api/mail/oauth/start` | JSON `OAuthStartIn` `{provider: str, email: str(3..=320), days=7}` | 200 `{"authorization_url", "state", "message_origin": public_backend_url}` | 400 `"Enter a valid email address"`, 400 `"Unsupported OAuth provider"`, 400 `"The OAuth provider does not match this email address"`, 429, 503 `OAuthError`, 422 |
//! | GET    | `/api/mail/oauth/{provider}/callback` | query `state: str(max 200)=""`, `code: str(max 8192)=""`, `error: str(max 500)=""` | 200 HTML page posting `{"type":"email-doctor-oauth","jobId"}` or `{..., "error"}` to the extension origin that started the flow (else `frontend_url`); headers `Cache-Control: no-store`, `Referrer-Policy: no-referrer` (query string must never be logged) | 422 |
//! | GET    | `/api/jobs` | — | 200 `[JobOut]` (log blanked) | — |
//! | GET    | `/api/jobs/{job_id}` | — | 200 `JobOut` (+ `output_files` when completed) | 404 `"Job not found"` |
//! | GET    | `/api/jobs/{job_id}/files` | — | 200 `{"files": [rel paths]}` | 404, 400 `"Job is not completed"` |
//! | GET    | `/api/jobs/{job_id}/snapshot-files` | — | 200 `{"files": [...]}` | 404 `"Job not found"` / `"No audit snapshot is available yet"` |
//! | GET    | `/api/jobs/{job_id}/files/{*rel_path}` | — | 200 bytes; type by extension (`.md`/`.jsonl` → `text/plain`), `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`, `Content-Security-Policy: sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:` on every file (Python: `.html` only) | 404 `"Job not found"`/`"File not found"`, 400 `"Job is not completed"` |
//! | GET    | `/api/jobs/{job_id}/snapshot-files/{*rel_path}` | — | as above (outputs or snapshot_outputs) | 404 incl. `"No audit snapshot is available yet"` |
//! | POST   | `/api/jobs/{job_id}/discard` | — | 200 `JobOut` | 404, 400 `"Job was already discarded"` |
//! | GET    | `/api/jobs/{job_id}/download-zip` | — | 200 `application/zip`, `Content-Disposition: attachment; filename*=utf-8''{quote(stem)}_audit.zip`, no-store, nosniff | 404 `"Job not found"`/`"ZIP archive not found"`, 400 `"Job is not completed"` |
//!
//! OAuth from the extension: the sign-in window is opened by an extension
//! page, so the callback page (served by this backend) must `postMessage` to
//! that page's `chrome-extension://…` origin. `POST /api/mail/oauth/start`
//! therefore stores the request's `Origin` with the pending flow when it is
//! an extension origin (it already passed [`crate::security::guard`]); the
//! callback posts there and falls back to `frontend_url` otherwise.
//!
//! Upload bodies are spooled like Starlette's `UploadFile`
//! (`SpooledTemporaryFile`): up to 1 MiB in memory, larger parts in an
//! anonymous owner-only (0600) temporary file that the OS deletes when the
//! request ends — Python's `SpooledTemporaryFile` rolls over to
//! `TemporaryFile` with the same properties.
//!
//! Deviations: a multipart body the parser cannot read is a 400
//! `"There was an error parsing the body"` (as FastAPI answers parser
//! exceptions); `GET /api/jobs/{id}/files/` (empty relative path) answers
//! like Python (`"File not found"` once the job is completed).

use std::convert::Infallible;
use std::future::Future;
use std::io::Read;

use axum::body::Bytes;
use axum::extract::{FromRequest, Multipart, Path, Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use mail_core::schemas::RequestModel;
use mail_doctor::oauth::CALLBACK_HEADERS;
use mail_doctor::runner::{FileResponse, JobRunner, UploadFile};
use mail_doctor::schemas::{AccountJobIn, JobOut, MailCredentialsIn, OAuthStartIn, PasteJobIn};
use serde_json::{json, Value};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use tower::{Layer, ServiceExt};

use crate::error::{run_blocking, ApiError, ApiResult};
use crate::extract::{issue_with_ctx, missing_issue, JsonObject, QueryParams, BODY_PARSE_ERROR};
use crate::limits::{RequestSizeLimitLayer, REQUEST_TOO_LARGE};
use crate::security;
use crate::state::AppState;

/// Starlette `MultiPartParser` defaults (`max_files`, `max_fields`).
const MAX_FORM_FILES: usize = 1000;
const MAX_FORM_FIELDS: usize = 1000;
/// Starlette's `max_part_size` for non-file fields (1 MiB).
const MAX_FIELD_PART_BYTES: usize = 1024 * 1024;
/// `SpooledTemporaryFile(max_size=1024 * 1024)` of Starlette's `UploadFile`.
const SPOOL_MEMORY_BYTES: usize = 1024 * 1024;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/jobs", get(list_jobs).post(create_job))
        // FastAPI falls through to `GET /api/jobs/{job_id}` for this path.
        .route("/api/jobs/paste", post(create_paste_job).get(get_paste_job))
        .route("/api/mail/providers", get(mail_providers))
        .route("/api/mail/jobs/account", post(create_account_job))
        .route("/api/mail/jobs", post(create_credentials_job))
        .route("/api/mail/oauth/start", post(start_oauth))
        .route("/api/mail/oauth/{provider}/callback", get(oauth_callback))
        .route("/api/jobs/{job_id}", get(get_job))
        .route("/api/jobs/{job_id}/files", get(list_output_files))
        .route("/api/jobs/{job_id}/files/", get(get_output_file_root))
        .route("/api/jobs/{job_id}/files/{*rel_path}", get(get_output_file))
        .route(
            "/api/jobs/{job_id}/snapshot-files",
            get(list_snapshot_files),
        )
        .route(
            "/api/jobs/{job_id}/snapshot-files/",
            get(get_snapshot_file_root),
        )
        .route(
            "/api/jobs/{job_id}/snapshot-files/{*rel_path}",
            get(get_snapshot_file),
        )
        .route("/api/jobs/{job_id}/discard", post(discard_job))
        .route("/api/jobs/{job_id}/download-zip", get(download_zip))
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn created(job: JobOut) -> Response {
    (StatusCode::CREATED, Json(job)).into_response()
}

fn into_response(result: ApiResult<Response>) -> Response {
    result.unwrap_or_else(IntoResponse::into_response)
}

/// Apply `RequestSizeLimitLayer::doctor_upload` with this application's
/// `max_upload_bytes` (Python's `UploadLimitMiddleware` read
/// `app.state.doctor.settings` per request) around `handler`.
async fn with_upload_limit<F, Fut>(state: AppState, request: Request, handler: F) -> Response
where
    F: Fn(AppState, Request) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Response> + Send + 'static,
{
    let limit = RequestSizeLimitLayer::doctor_upload(state.doctor.settings().max_upload_bytes);
    let service = tower::service_fn(move |request: Request| {
        let response = handler(state.clone(), request);
        async move { Ok::<_, Infallible>(response.await) }
    });
    match limit.layer(service).oneshot(request).await {
        Ok(response) => response,
        Err(never) => match never {},
    }
}

/// A complete file read under the runner lock, as a Starlette `Response`.
fn file_response(file: FileResponse) -> ApiResult<Response> {
    let mut response = Response::new(axum::body::Body::from(file.body));
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&file.media_type).map_err(|_| ApiError::internal())?,
    );
    for (name, value) in file.headers {
        headers.insert(
            HeaderName::from_bytes(name.as_bytes()).map_err(|_| ApiError::internal())?,
            HeaderValue::from_str(&value).map_err(|_| ApiError::internal())?,
        );
    }
    Ok(response)
}

fn runner(state: &AppState) -> JobRunner {
    state.doctor.clone()
}

// ---------------------------------------------------------------------------
// Upload spooling (Starlette `UploadFile`)
// ---------------------------------------------------------------------------

/// The content of one uploaded file.
enum Spool {
    Memory(Vec<u8>),
    /// An anonymous temporary file ([`private_tempfile`]): owner-only
    /// permissions (0600 on Unix, set explicitly), never linked under a guessable
    /// name (`O_TMPFILE` / unlinked on Unix, `FILE_FLAG_DELETE_ON_CLOSE` on
    /// Windows) and removed by the OS once the last handle is closed, even
    /// when the process dies. Positioned at the start of the content.
    File(std::fs::File),
}

/// An anonymous temporary file that is private to the owner.
///
/// [`tempfile::tempfile`] only guarantees 0600 on its fallback path: on Linux
/// it opens with `O_TMPFILE` and the default mode (0666 & !umask, typically
/// 0644). The mode is therefore set explicitly (`fchmod` on the open handle).
fn private_tempfile() -> std::io::Result<std::fs::File> {
    let file = tempfile::tempfile()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

/// Spool writer: memory first, a temporary file past [`SPOOL_MEMORY_BYTES`].
struct SpoolWriter {
    memory: Vec<u8>,
    file: Option<tokio::fs::File>,
}

impl SpoolWriter {
    fn new() -> Self {
        Self {
            memory: Vec::new(),
            file: None,
        }
    }

    async fn write(&mut self, chunk: &[u8]) -> std::io::Result<()> {
        if self.file.is_none() && self.memory.len() + chunk.len() <= SPOOL_MEMORY_BYTES {
            self.memory.extend_from_slice(chunk);
            return Ok(());
        }
        let file = match self.file.as_mut() {
            Some(file) => file,
            None => {
                let spooled = tokio::task::spawn_blocking(private_tempfile)
                    .await
                    .map_err(std::io::Error::other)??;
                let mut file = tokio::fs::File::from_std(spooled);
                file.write_all(&std::mem::take(&mut self.memory)).await?;
                self.file.insert(file)
            }
        };
        file.write_all(chunk).await
    }

    async fn finish(self) -> std::io::Result<Spool> {
        match self.file {
            None => Ok(Spool::Memory(self.memory)),
            Some(mut file) => {
                file.flush().await?;
                file.seek(std::io::SeekFrom::Start(0)).await?;
                Ok(Spool::File(file.into_std().await))
            }
        }
    }
}

/// One `files` form value: an uploaded file or (invalid) plain text.
enum FilesValue {
    File {
        filename: Option<String>,
        spool: Spool,
    },
    Text(String),
}

fn content_type(headers: &HeaderMap) -> String {
    headers
        .get(header::CONTENT_TYPE)
        .map(|value| value.as_bytes().iter().map(|&b| b as char).collect())
        .unwrap_or_default()
}

fn has_boundary(content_type: &str) -> bool {
    content_type.split(';').skip(1).any(|param| {
        param.split_once('=').is_some_and(|(name, value)| {
            name.trim().eq_ignore_ascii_case("boundary")
                && !value.trim().trim_matches('"').is_empty()
        })
    })
}

fn multipart_error(error: axum::extract::multipart::MultipartError) -> ApiError {
    if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
        ApiError::payload_too_large(REQUEST_TOO_LARGE)
    } else {
        ApiError::bad_request(BODY_PARSE_ERROR)
    }
}

fn spool_error(_: std::io::Error) -> ApiError {
    ApiError::internal()
}

/// FastAPI's `await request.form()` for a route with `File` parameters,
/// returning the values of the `files` field in order. Bodies that are not
/// forms yield no values.
async fn read_files_field(request: Request) -> ApiResult<Vec<FilesValue>> {
    let content_type = content_type(request.headers());
    let essence = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    match essence.as_str() {
        "multipart/form-data" => {
            if !has_boundary(&content_type) {
                return Err(ApiError::bad_request(BODY_PARSE_ERROR));
            }
            let mut multipart = Multipart::from_request(request, &())
                .await
                .map_err(|_| ApiError::bad_request(BODY_PARSE_ERROR))?;
            let mut values = Vec::new();
            let (mut files, mut fields) = (0usize, 0usize);
            while let Some(mut field) = multipart.next_field().await.map_err(multipart_error)? {
                let wanted = field.name() == Some("files");
                match field.file_name().map(str::to_string) {
                    Some(filename) => {
                        files += 1;
                        if files > MAX_FORM_FILES {
                            return Err(ApiError::bad_request(BODY_PARSE_ERROR));
                        }
                        let mut writer = SpoolWriter::new();
                        while let Some(chunk) = field.chunk().await.map_err(multipart_error)? {
                            if wanted {
                                writer.write(&chunk).await.map_err(spool_error)?;
                            }
                        }
                        if wanted {
                            values.push(FilesValue::File {
                                filename: Some(filename),
                                spool: writer.finish().await.map_err(spool_error)?,
                            });
                        }
                    }
                    None => {
                        fields += 1;
                        if fields > MAX_FORM_FIELDS {
                            return Err(ApiError::bad_request(BODY_PARSE_ERROR));
                        }
                        let mut data = Vec::new();
                        while let Some(chunk) = field.chunk().await.map_err(multipart_error)? {
                            if data.len() + chunk.len() > MAX_FIELD_PART_BYTES {
                                return Err(ApiError::bad_request(BODY_PARSE_ERROR));
                            }
                            data.extend_from_slice(&chunk);
                        }
                        if wanted {
                            values.push(FilesValue::Text(
                                String::from_utf8_lossy(&data).into_owned(),
                            ));
                        }
                    }
                }
            }
            Ok(values)
        }
        "application/x-www-form-urlencoded" => {
            let bytes = Bytes::from_request(request, &())
                .await
                .map_err(|rejection| {
                    if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
                        ApiError::payload_too_large(REQUEST_TOO_LARGE)
                    } else {
                        ApiError::bad_request(BODY_PARSE_ERROR)
                    }
                })?;
            Ok(url::form_urlencoded::parse(&bytes)
                .filter(|(name, _)| name == "files")
                .map(|(_, value)| FilesValue::Text(value.into_owned()))
                .collect())
        }
        _ => Ok(Vec::new()),
    }
}

/// Validate `files: list[UploadFile] = File(...)` like FastAPI/pydantic.
fn validate_files_field(values: Vec<FilesValue>) -> ApiResult<Vec<(Option<String>, Spool)>> {
    if values.is_empty() {
        return Err(ApiError::validation(vec![missing_issue(
            vec![json!("body"), json!("files")],
            Value::Null,
        )]));
    }
    let issues: Vec<Value> = values
        .iter()
        .enumerate()
        .filter_map(|(index, value)| match value {
            FilesValue::Text(text) => Some(issue_with_ctx(
                "value_error",
                vec![json!("body"), json!("files"), json!(index)],
                "Value error, Expected UploadFile, received: <class 'str'>",
                json!(text),
                json!({"error": {}}),
            )),
            FilesValue::File { .. } => None,
        })
        .collect();
    if !issues.is_empty() {
        return Err(ApiError::validation(issues));
    }
    Ok(values
        .into_iter()
        .filter_map(|value| match value {
            FilesValue::File { filename, spool } => Some((filename, spool)),
            FilesValue::Text(_) => None,
        })
        .collect())
}

// ---------------------------------------------------------------------------
// Job creation
// ---------------------------------------------------------------------------

/// `POST /api/jobs` (multipart `files`).
async fn create_job(State(state): State<AppState>, request: Request) -> Response {
    with_upload_limit(state, request, |state, request| async move {
        into_response(create_job_inner(state, request).await)
    })
    .await
}

async fn create_job_inner(state: AppState, request: Request) -> ApiResult<Response> {
    let values = read_files_field(request).await?;
    let files = validate_files_field(values)?;
    let doctor = runner(&state);
    let job = run_blocking(move || {
        // Each reader owns its spool, so a temporary file is closed (and
        // deleted by the OS) once staging has consumed it, or when the
        // request fails or is dropped.
        let uploads = files
            .into_iter()
            .map(|(filename, spool)| {
                let reader: Box<dyn Read + Send> = match spool {
                    Spool::Memory(bytes) => Box::new(std::io::Cursor::new(bytes)),
                    Spool::File(file) => Box::new(file),
                };
                UploadFile { filename, reader }
            })
            .collect();
        doctor.create_upload_job(uploads)
    })
    .await?;
    Ok(created(job))
}

/// `POST /api/jobs/paste`.
async fn create_paste_job(State(state): State<AppState>, request: Request) -> Response {
    with_upload_limit(state, request, |state, request| async move {
        into_response(create_paste_job_inner(state, request).await)
    })
    .await
}

async fn create_paste_job_inner(state: AppState, request: Request) -> ApiResult<Response> {
    let JsonObject(body) = JsonObject::from_request(request, &()).await?;
    let body = PasteJobIn::from_json(&Value::Object(body))?;
    let doctor = runner(&state);
    let job = run_blocking(move || doctor.create_paste_job(&body)).await?;
    Ok(created(job))
}

/// `GET /api/mail/providers?email=`.
async fn mail_providers(
    State(state): State<AppState>,
    query: QueryParams,
) -> ApiResult<Json<Value>> {
    let mut q = query.validator();
    let email = q.string("email").max_length(320).default("");
    q.finish()?;
    Ok(Json(state.doctor.mail_providers(&email)))
}

/// `POST /api/mail/jobs/account`: audit an unlocked account.
async fn create_account_job(
    State(state): State<AppState>,
    JsonObject(body): JsonObject,
) -> ApiResult<Response> {
    let body = AccountJobIn::from_json(&Value::Object(body))?;
    let doctor = runner(&state);
    let sessions = state.sessions.clone();
    let job = run_blocking(move || doctor.create_account_job(&sessions, &body)).await?;
    Ok(created(job))
}

/// `POST /api/mail/jobs`: audit with separately supplied credentials.
async fn create_credentials_job(
    State(state): State<AppState>,
    JsonObject(body): JsonObject,
) -> ApiResult<Response> {
    let body = MailCredentialsIn::from_json(&Value::Object(body))?;
    let doctor = runner(&state);
    let job = run_blocking(move || doctor.create_credentials_job(&body)).await?;
    Ok(created(job))
}

// ---------------------------------------------------------------------------
// OAuth
// ---------------------------------------------------------------------------

/// The request's `Origin` when it is a browser-extension origin.
fn extension_origin(headers: &HeaderMap) -> Option<String> {
    let origin = headers.get(header::ORIGIN)?;
    if !security::origin_allowed(origin.as_bytes()) {
        return None;
    }
    origin.to_str().ok().map(|text| text.trim().to_string())
}

/// `POST /api/mail/oauth/start`.
async fn start_oauth(
    State(state): State<AppState>,
    headers: HeaderMap,
    JsonObject(body): JsonObject,
) -> ApiResult<Json<Value>> {
    let body = OAuthStartIn::from_json(&Value::Object(body))?;
    let origin = extension_origin(&headers);
    let doctor = runner(&state);
    let started =
        run_blocking(move || doctor.start_oauth_for_origin(&body, origin.as_deref())).await?;
    Ok(Json(started))
}

/// `GET /api/mail/oauth/{provider}/callback`: the page posting the result to
/// the opener. The request logger never records query strings, so the
/// authorization code and state stay out of the log.
async fn oauth_callback(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    query: QueryParams,
) -> ApiResult<Response> {
    let mut q = query.validator();
    let flow_state = q.string("state").max_length(200).default("");
    let code = q.string("code").max_length(8192).default("");
    let error = q.string("error").max_length(500).default("");
    q.finish()?;
    let doctor = runner(&state);
    let page =
        run_blocking(move || doctor.oauth_callback(&provider, &flow_state, &code, &error)).await?;
    let mut response = Html(page).into_response();
    for (name, value) in CALLBACK_HEADERS {
        response.headers_mut().insert(
            HeaderName::from_bytes(name.as_bytes()).map_err(|_| ApiError::internal())?,
            HeaderValue::from_static(value),
        );
    }
    Ok(response)
}

// ---------------------------------------------------------------------------
// Job reads
// ---------------------------------------------------------------------------

/// `GET /api/jobs`.
async fn list_jobs(State(state): State<AppState>) -> ApiResult<Json<Vec<JobOut>>> {
    let doctor = runner(&state);
    Ok(Json(run_blocking(move || doctor.list_jobs()).await?))
}

async fn job_by_id(state: &AppState, job_id: String) -> ApiResult<Json<JobOut>> {
    let doctor = runner(state);
    Ok(Json(run_blocking(move || doctor.get_job(&job_id)).await?))
}

/// `GET /api/jobs/{job_id}`.
async fn get_job(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> ApiResult<Json<JobOut>> {
    job_by_id(&state, job_id).await
}

/// `GET /api/jobs/paste` (FastAPI routes it to `get_job("paste")`).
async fn get_paste_job(State(state): State<AppState>) -> ApiResult<Json<JobOut>> {
    job_by_id(&state, "paste".to_string()).await
}

/// `GET /api/jobs/{job_id}/files`.
async fn list_output_files(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> ApiResult<Json<Value>> {
    let doctor = runner(&state);
    let files = run_blocking(move || doctor.list_output_files(&job_id)).await?;
    Ok(Json(json!({ "files": files })))
}

/// `GET /api/jobs/{job_id}/snapshot-files`.
async fn list_snapshot_files(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> ApiResult<Json<Value>> {
    let doctor = runner(&state);
    let files = run_blocking(move || doctor.list_snapshot_files(&job_id)).await?;
    Ok(Json(json!({ "files": files })))
}

async fn read_file(
    state: &AppState,
    job_id: String,
    rel_path: String,
    snapshot: bool,
) -> ApiResult<Response> {
    let doctor = runner(state);
    let file = run_blocking(move || doctor.read_job_file(&job_id, &rel_path, snapshot)).await?;
    file_response(file)
}

/// `GET /api/jobs/{job_id}/files/{rel_path:path}`.
async fn get_output_file(
    State(state): State<AppState>,
    Path((job_id, rel_path)): Path<(String, String)>,
) -> ApiResult<Response> {
    read_file(&state, job_id, rel_path, false).await
}

/// `GET /api/jobs/{job_id}/files/` (Starlette's `path` convertor matches
/// the empty relative path).
async fn get_output_file_root(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> ApiResult<Response> {
    read_file(&state, job_id, String::new(), false).await
}

/// `GET /api/jobs/{job_id}/snapshot-files/{rel_path:path}`.
async fn get_snapshot_file(
    State(state): State<AppState>,
    Path((job_id, rel_path)): Path<(String, String)>,
) -> ApiResult<Response> {
    read_file(&state, job_id, rel_path, true).await
}

/// `GET /api/jobs/{job_id}/snapshot-files/`.
async fn get_snapshot_file_root(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> ApiResult<Response> {
    read_file(&state, job_id, String::new(), true).await
}

/// `POST /api/jobs/{job_id}/discard`.
async fn discard_job(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> ApiResult<Json<JobOut>> {
    let doctor = runner(&state);
    Ok(Json(run_blocking(move || doctor.discard(&job_id)).await?))
}

/// `GET /api/jobs/{job_id}/download-zip`.
async fn download_zip(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> ApiResult<Response> {
    let doctor = runner(&state);
    let file = run_blocking(move || doctor.download_zip(&job_id)).await?;
    file_response(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn small_uploads_stay_in_memory() {
        let mut writer = SpoolWriter::new();
        writer.write(b"hello").await.unwrap();
        match writer.finish().await.unwrap() {
            Spool::Memory(bytes) => assert_eq!(bytes, b"hello"),
            Spool::File(_) => panic!("small upload spooled to disk"),
        }
    }

    #[tokio::test]
    async fn large_uploads_roll_over_to_a_private_anonymous_file() {
        let first = vec![b'a'; SPOOL_MEMORY_BYTES - 10];
        let second = vec![b'b'; 64];
        let mut writer = SpoolWriter::new();
        writer.write(&first).await.unwrap();
        writer.write(&second).await.unwrap();
        writer.write(b"tail").await.unwrap();
        let Spool::File(mut file) = writer.finish().await.unwrap() else {
            panic!("large upload kept in memory");
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = file.metadata().unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "{mode:o}");
        }
        let mut content = Vec::new();
        file.read_to_end(&mut content).unwrap();
        let mut expected = first;
        expected.extend_from_slice(&second);
        expected.extend_from_slice(b"tail");
        assert_eq!(content, expected);
    }
}
