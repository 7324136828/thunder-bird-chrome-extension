//! Remote image privacy proxy fetcher (port of `app/mail/remote_images.py`).
//!
//! # Fixed public contract (Phase 2)
//! `fetch_image` is called from the image route via `spawn_blocking`;
//! `clear_cache` from `AppState::shutdown`.
//!
//! Fetch email images without browser credentials or access to private
//! networks. Callers must authorize a URL against the selected email before
//! calling this module. All connections use the public IP addresses that
//! were checked during resolution; HTTPS still verifies the certificate
//! against the original hostname.
//!
//! # Transport
//!
//! The downloader drives its own HTTP/1.1 exchange over a `std::net::
//! TcpStream` (wrapped in `native_tls` for HTTPS) instead of using reqwest:
//!
//! * every hop resolves exactly once and connects to the vetted
//!   [`SocketAddr`] itself, so there is no second lookup a DNS-rebinding
//!   attacker could answer differently, and no connection pool, proxy
//!   setting or happy-eyeballs logic that might connect elsewhere;
//! * redirects are never followed by a library: each `Location` goes back
//!   through URL validation and resolution;
//! * the response framing reproduces `http.client` exactly (status line,
//!   header parsing, `read1` streaming with the byte cap), with a
//!   per-read socket timeout and a watchdog that shuts the socket down at the
//!   total deadline, like Python's `threading.Timer`.
//!
//! TLS uses the platform verifier with the URL's hostname (SNI and
//! certificate check), never the IP address that was dialed.
//!
//! # Tests
//!
//! Module-level [`fetch_image`] / [`clear_cache`] use one process-wide
//! [`ImageFetcher`] built from [`FetcherConfig::default`] (system resolver,
//! every record vetted). Tests build their own `ImageFetcher` with a smaller
//! [`FetcherConfig`] and, to reach local test servers, a
//! [`Resolver::UnvettedForTests`] (the equivalent of patching `_resolve` in
//! the Python tests). Only debug builds can swap the process-wide fetcher
//! ([`replace_global_fetcher_for_tests`]); release builds have no hook that
//! weakens the production checks.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{mpsc, Arc, Condvar, LazyLock, Mutex, MutexGuard, RwLock};
use std::time::{Duration, Instant};

use crate::image_sources::ip;
use crate::image_sources::urllib::{idna_encode, quote, urljoin, urlsplit, urlunsplit};

#[path = "images_parts/http.rs"]
mod http;

use http::{Connection, ProtocolError, Response, Stream, Watchdog};

/// `MAX_IMAGE_BYTES`.
pub const MAX_IMAGE_BYTES: usize = 10 * 1024 * 1024;
/// `MAX_IMAGE_PIXELS`.
pub const MAX_IMAGE_PIXELS: u64 = 25_000_000;
/// `MAX_REDIRECTS`.
pub const MAX_REDIRECTS: usize = 4;
/// `DOWNLOAD_TIMEOUT`: total time for one image, redirects included.
pub const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(20);
/// `SOCKET_TIMEOUT`: connect / single read inactivity limit.
pub const SOCKET_TIMEOUT: Duration = Duration::from_secs(8);
/// `MAX_CONCURRENT_DOWNLOADS` (also bounds outstanding DNS lookups).
pub const MAX_CONCURRENT_DOWNLOADS: usize = 4;
/// `CACHE_MAX_ENTRIES`.
pub const CACHE_MAX_ENTRIES: usize = 32;
/// `CACHE_MAX_BYTES`.
pub const CACHE_MAX_BYTES: usize = 64 * 1024 * 1024;
/// `CACHE_SUCCESS_SECONDS`.
pub const CACHE_SUCCESS: Duration = Duration::from_secs(60 * 60);
/// `CACHE_FAILURE_SECONDS`.
pub const CACHE_FAILURE: Duration = Duration::from_secs(5 * 60);

const TIMED_OUT: &str = "The image download timed out.";
const FAILED: &str = "The image download failed.";
const UNREACHABLE: &str = "The image host could not be reached.";
const BLOCKED: &str = "Private network image addresses are blocked.";
const TOO_MANY_REDIRECTS: &str = "The image redirected too many times.";
const UNSUPPORTED: &str = "The response was not a supported image.";

/// `ImageDownloadError` (the route maps it exactly as main.py did).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ImageDownloadError(pub String);

impl ImageDownloadError {
    fn new(message: &str) -> Self {
        Self(message.to_string())
    }
}

impl From<ProtocolError> for ImageDownloadError {
    fn from(_: ProtocolError) -> Self {
        Self::new(FAILED)
    }
}

impl From<io::Error> for ImageDownloadError {
    fn from(_: io::Error) -> Self {
        Self::new(FAILED)
    }
}

type Result<T> = std::result::Result<T, ImageDownloadError>;

/// `DownloadedImage`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadedImage {
    pub content: Vec<u8>,
    pub content_type: String,
}

// ---------------------------------------------------------------------------
// URL validation
// ---------------------------------------------------------------------------

/// `_Target`: one validated request target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub scheme: String,
    /// IDNA-encoded, lowercased hostname (IPv6 literals without brackets).
    pub host: String,
    pub port: u16,
    /// Request path including `?query`.
    pub path: String,
    /// Canonical URL (cache key).
    pub url: String,
}

/// `_remaining`.
fn remaining(deadline: Instant) -> Result<Duration> {
    let now = Instant::now();
    if deadline <= now {
        return Err(ImageDownloadError::new(TIMED_OUT));
    }
    Ok(deadline - now)
}

/// `_target`: validate and canonicalize an image URL.
pub fn target(url: &str) -> Result<Target> {
    let invalid = || ImageDownloadError::new("The image URL is invalid.");
    if url.is_empty() || url.chars().count() > 8192 {
        return Err(invalid());
    }
    if url.contains('\\') || url.chars().any(|c| c as u32 <= 32 || c as u32 == 127) {
        return Err(invalid());
    }
    target_inner(url).ok_or_else(|| ImageDownloadError::new("The image URL is not permitted."))
}

fn target_inner(url: &str) -> Option<Target> {
    let parsed = urlsplit(url, "").ok()?;
    if parsed.scheme != "http" && parsed.scheme != "https" {
        return None;
    }
    let hostname = parsed.hostname()?;
    if parsed.username().is_some() || parsed.password().is_some() {
        return None;
    }
    let host = idna_encode(hostname.trim_end_matches('.'))
        .ok()?
        .to_lowercase();
    let default_port = if parsed.scheme == "https" { 443 } else { 80 };
    let port = parsed.port().ok()?.unwrap_or(default_port);
    if host.is_empty() || host.contains('%') || !(port == 80 || port == 443) {
        return None;
    }
    if host == "localhost"
        || host == "metadata"
        || [".localhost", ".local", ".internal", ".lan", ".home"]
            .iter()
            .any(|suffix| host.ends_with(suffix))
    {
        return None;
    }
    let mut authority = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.clone()
    };
    if port != default_port {
        authority = format!("{authority}:{port}");
    }
    let path = quote(
        if parsed.path.is_empty() {
            "/"
        } else {
            &parsed.path
        },
        "/%:@!$&'()*+,;=-._~",
    );
    let query = quote(&parsed.query, "/%?:@!$&'()*+,;=-._~");
    let request_path = if query.is_empty() {
        path.clone()
    } else {
        format!("{path}?{query}")
    };
    Some(Target {
        url: urlunsplit(&parsed.scheme, &authority, &path, &query, ""),
        scheme: parsed.scheme,
        host,
        port,
        path: request_path,
    })
}

/// `urljoin(base, location)` for a redirect (`Err` where Python raised
/// `ValueError`, which `_download` reported as a failed download).
pub fn redirect_url(base: &str, location: &str) -> Result<String> {
    urljoin(base, location).map_err(|_| ImageDownloadError::new(FAILED))
}

/// `_public_address(address)` for a textual address.
pub fn public_address(address: &str) -> bool {
    ip::parse_ip(address).is_some_and(|(address, _)| ip::public_address(address))
}

/// `_public_address` for a resolved socket address.
pub fn public_ip(address: IpAddr) -> bool {
    ip::public_address(address)
}

/// The vetting `_resolve` applies to every resolution result: rejects an
/// empty or oversized answer and any non-public record (mixed public/private
/// answers are rejected as a whole).
pub fn vet_records(records: &[SocketAddr]) -> Result<()> {
    if records.is_empty()
        || records.len() > 32
        || records.iter().any(|record| !public_ip(record.ip()))
    {
        return Err(ImageDownloadError::new(BLOCKED));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Request headers and image checks
// ---------------------------------------------------------------------------

fn token_hex(bytes: usize) -> Result<String> {
    let mut buffer = vec![0u8; bytes];
    getrandom::fill(&mut buffer).map_err(|_| ImageDownloadError::new(FAILED))?;
    Ok(hex::encode(buffer))
}

/// `_headers`: disposable values unrelated to the user, their account, or
/// any cookies returned by this or another server. Every redirect gets new
/// values.
pub fn request_headers() -> Result<Vec<(&'static str, String)>> {
    Ok(vec![
        ("User-Agent", "Mozilla/5.0".to_string()),
        (
            "Accept",
            "image/png,image/jpeg,image/gif,image/webp,image/bmp".to_string(),
        ),
        ("Accept-Encoding", "identity".to_string()),
        ("Connection", "close".to_string()),
        ("X-Image-Request", token_hex(16)?),
        ("Cookie", format!("image_session={}", token_hex(24)?)),
    ])
}

/// `_dimensions`.
fn dimensions(width: i64, height: i64) -> Result<()> {
    if width <= 0 || height <= 0 || (width as u64) * (height as u64) > MAX_IMAGE_PIXELS {
        return Err(ImageDownloadError::new(
            "The image dimensions are not permitted.",
        ));
    }
    Ok(())
}

fn be16(content: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([content[offset], content[offset + 1]])
}

fn be32(content: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(content[offset..offset + 4].try_into().expect("4 bytes"))
}

fn le16(content: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([content[offset], content[offset + 1]])
}

fn le32(content: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(content[offset..offset + 4].try_into().expect("4 bytes"))
}

/// `_image_type`: check raster signatures, framing, and dimensions; never
/// serve SVG/HTML.
pub fn image_type(content: &[u8]) -> Result<&'static str> {
    let unsupported = || Err(ImageDownloadError::new(UNSUPPORTED));
    let length = content.len();
    if content.starts_with(b"\x89PNG\r\n\x1a\n") {
        let mut offset = 8;
        let (mut saw_header, mut saw_data, mut saw_end) = (false, false, false);
        while offset + 12 <= length {
            let chunk_length = be32(content, offset) as usize;
            let end = offset + 12 + chunk_length;
            if end > length {
                break;
            }
            let kind = &content[offset + 4..offset + 8];
            let data = &content[offset + 8..offset + 8 + chunk_length];
            let crc = be32(content, offset + 8 + chunk_length);
            let mut hasher = crc32fast::Hasher::new();
            hasher.update(kind);
            hasher.update(data);
            if hasher.finalize() != crc {
                break;
            }
            if !saw_header {
                if kind != b"IHDR" || chunk_length != 13 {
                    break;
                }
                dimensions(be32(data, 0) as i64, be32(data, 4) as i64)?;
                saw_header = true;
            } else if kind == b"IHDR" {
                break;
            }
            if kind == b"IDAT" {
                saw_data = true;
            }
            if kind == b"IEND" {
                saw_end = chunk_length == 0 && end == length;
                break;
            }
            offset = end;
        }
        if saw_header && saw_data && saw_end {
            return Ok("image/png");
        }
    } else if content.starts_with(b"GIF87a") || content.starts_with(b"GIF89a") {
        if length >= 14 && content.ends_with(b";") {
            dimensions(le16(content, 6) as i64, le16(content, 8) as i64)?;
            return Ok("image/gif");
        }
    } else if content.starts_with(b"\xff\xd8") && content.ends_with(b"\xff\xd9") {
        let mut offset = 2;
        while offset + 4 <= length {
            if content[offset] != 0xFF {
                break;
            }
            while offset < length && content[offset] == 0xFF {
                offset += 1;
            }
            if offset + 3 > length {
                break;
            }
            let marker = content[offset];
            offset += 1;
            if marker == 0x01 || (0xD0..0xDA).contains(&marker) {
                continue;
            }
            let segment = be16(content, offset) as usize;
            if segment < 2 || offset + segment > length {
                break;
            }
            if matches!(
                marker,
                0xC0 | 0xC1
                    | 0xC2
                    | 0xC3
                    | 0xC5
                    | 0xC6
                    | 0xC7
                    | 0xC9
                    | 0xCA
                    | 0xCB
                    | 0xCD
                    | 0xCE
                    | 0xCF
            ) {
                if segment >= 8 {
                    let height = be16(content, offset + 3);
                    let width = be16(content, offset + 5);
                    dimensions(width as i64, height as i64)?;
                    return Ok("image/jpeg");
                }
                break;
            }
            if marker == 0xDA {
                break;
            }
            offset += segment;
        }
    } else if length >= 30 && &content[..4] == b"RIFF" && &content[8..12] == b"WEBP" {
        if le32(content, 4) as usize + 8 == length {
            let kind = &content[12..16];
            let chunk_length = le32(content, 16) as usize;
            if chunk_length + 20 <= length {
                let (width, height) = if kind == b"VP8X" && chunk_length == 10 {
                    (
                        u32::from_le_bytes([content[24], content[25], content[26], 0]) as i64 + 1,
                        u32::from_le_bytes([content[27], content[28], content[29], 0]) as i64 + 1,
                    )
                } else if kind == b"VP8 " && content[23..26] == [0x9d, 0x01, 0x2a] {
                    (
                        (le16(content, 26) & 0x3FFF) as i64,
                        (le16(content, 28) & 0x3FFF) as i64,
                    )
                } else if kind == b"VP8L" && content[20] == 0x2F {
                    let packed = le32(content, 21);
                    (
                        (packed & 0x3FFF) as i64 + 1,
                        ((packed >> 14) & 0x3FFF) as i64 + 1,
                    )
                } else {
                    return unsupported();
                };
                dimensions(width, height)?;
                return Ok("image/webp");
            }
        }
    } else if length >= 54 && &content[..2] == b"BM" {
        let file_size = le32(content, 2) as usize;
        let pixel_offset = le32(content, 10) as usize;
        let dib_size = le32(content, 14) as usize;
        if file_size == length
            && dib_size >= 40
            && 14 + dib_size <= pixel_offset
            && pixel_offset < length
        {
            let width = le32(content, 18) as i32 as i64;
            let height = le32(content, 22) as i32 as i64;
            dimensions(width, height.abs())?;
            return Ok("image/bmp");
        }
    }
    unsupported()
}

// ---------------------------------------------------------------------------
// Fetcher
// ---------------------------------------------------------------------------

/// A DNS lookup replacing the system resolver (records are still vetted).
pub type LookupFn = dyn Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + Sync;
/// A test-only replacement for the whole of `_resolve` (no vetting).
/// `None` falls back to the normal, vetted system resolution.
pub type UnvettedResolveFn = dyn Fn(&Target) -> Option<Vec<SocketAddr>> + Send + Sync;

/// How [`ImageFetcher`] turns a hostname into connectable addresses.
#[derive(Clone, Default)]
pub enum Resolver {
    /// `socket.getaddrinfo` on a bounded worker with the deadline; every
    /// record must pass [`vet_records`]. IP literals skip the lookup but are
    /// vetted too.
    #[default]
    System,
    /// Replace only the DNS lookup (Python tests patching
    /// `socket.getaddrinfo`); bounding, timeouts and vetting still apply.
    Lookup(Arc<LookupFn>),
    /// Tests only: connect to the returned records without vetting (Python
    /// tests patching `_resolve` to reach `127.0.0.1` servers); `None` uses
    /// the vetted system path. Never used by the process-wide production
    /// fetcher.
    UnvettedForTests(Arc<UnvettedResolveFn>),
}

impl std::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Resolver::System => "System",
            Resolver::Lookup(_) => "Lookup",
            Resolver::UnvettedForTests(_) => "UnvettedForTests",
        })
    }
}

/// The module constants as one value (Python tests patched them).
#[derive(Debug, Clone)]
pub struct FetcherConfig {
    pub max_image_bytes: usize,
    pub download_timeout: Duration,
    pub socket_timeout: Duration,
    pub max_concurrent_downloads: usize,
    pub cache_max_entries: usize,
    pub cache_max_bytes: usize,
    pub cache_success: Duration,
    pub cache_failure: Duration,
    pub resolver: Resolver,
}

impl Default for FetcherConfig {
    fn default() -> Self {
        Self {
            max_image_bytes: MAX_IMAGE_BYTES,
            download_timeout: DOWNLOAD_TIMEOUT,
            socket_timeout: SOCKET_TIMEOUT,
            max_concurrent_downloads: MAX_CONCURRENT_DOWNLOADS,
            cache_max_entries: CACHE_MAX_ENTRIES,
            cache_max_bytes: CACHE_MAX_BYTES,
            cache_success: CACHE_SUCCESS,
            cache_failure: CACHE_FAILURE,
            resolver: Resolver::System,
        }
    }
}

/// `threading.BoundedSemaphore` with a timed acquire.
#[derive(Debug)]
struct Semaphore {
    permits: Mutex<usize>,
    available: Condvar,
}

impl Semaphore {
    fn new(permits: usize) -> Self {
        Self {
            permits: Mutex::new(permits),
            available: Condvar::new(),
        }
    }

    fn acquire_timeout(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut permits = self.permits.lock().unwrap_or_else(|e| e.into_inner());
        while *permits == 0 {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            permits = self
                .available
                .wait_timeout(permits, deadline - now)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        *permits -= 1;
        true
    }

    fn release(&self) {
        *self.permits.lock().unwrap_or_else(|e| e.into_inner()) += 1;
        self.available.notify_one();
    }
}

/// Releases a download slot once.
struct SlotGuard<'a>(Option<&'a Semaphore>);

impl SlotGuard<'_> {
    fn release(&mut self) {
        if let Some(slots) = self.0.take() {
            slots.release();
        }
    }
}

impl Drop for SlotGuard<'_> {
    fn drop(&mut self) {
        self.release();
    }
}

/// `_CacheEntry`.
#[derive(Debug, Clone)]
struct CacheEntry {
    image: Option<DownloadedImage>,
    error: Option<String>,
    expires: Instant,
}

impl CacheEntry {
    /// `_result`.
    fn result(self) -> Result<DownloadedImage> {
        match self.image {
            Some(image) => Ok(image),
            None => Err(ImageDownloadError(
                self.error.unwrap_or_else(|| FAILED.to_string()),
            )),
        }
    }

    fn size(&self) -> usize {
        self.image.as_ref().map_or(0, |image| image.content.len())
    }
}

#[derive(Debug, Default)]
struct CacheState {
    /// Least recently used first (`OrderedDict` order).
    entries: VecDeque<(String, CacheEntry)>,
    bytes: usize,
    generation: u64,
    /// URL -> id of the download in progress (`_pending`).
    pending: HashMap<String, u64>,
    next_pending: u64,
}

impl CacheState {
    /// `_cached`.
    fn cached(&mut self, key: &str) -> Option<CacheEntry> {
        let index = self
            .entries
            .iter()
            .position(|(candidate, _)| candidate == key)?;
        let (key, entry) = self.entries.remove(index).expect("index is valid");
        if entry.expires <= Instant::now() {
            self.bytes -= entry.size();
            return None;
        }
        self.entries.push_back((key, entry.clone()));
        Some(entry)
    }

    /// `_remember`.
    fn remember(&mut self, key: &str, entry: CacheEntry, config: &FetcherConfig) {
        if let Some(index) = self
            .entries
            .iter()
            .position(|(candidate, _)| candidate == key)
        {
            let (_, previous) = self.entries.remove(index).expect("index is valid");
            self.bytes -= previous.size();
        }
        self.bytes += entry.size();
        self.entries.push_back((key.to_string(), entry));
        while self.entries.len() > config.cache_max_entries || self.bytes > config.cache_max_bytes {
            match self.entries.pop_front() {
                Some((_, old)) => self.bytes -= old.size(),
                None => break,
            }
        }
    }
}

/// The downloader with its cache, single-flight table and concurrency
/// limits (the module-level state of remote_images.py).
pub struct ImageFetcher {
    config: FetcherConfig,
    state: Mutex<CacheState>,
    changed: Condvar,
    download_slots: Semaphore,
    // A timed-out OS resolver can continue running. Its separate bound
    // prevents those lookups from growing with incoming email requests.
    dns_slots: Arc<Semaphore>,
}

impl std::fmt::Debug for ImageFetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImageFetcher")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// Removes the pending marker and wakes waiters, even on panic.
struct PendingGuard<'a> {
    fetcher: &'a ImageFetcher,
    key: String,
    id: u64,
}

impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        let mut state = self.fetcher.lock();
        if state.pending.get(&self.key) == Some(&self.id) {
            state.pending.remove(&self.key);
        }
        drop(state);
        self.fetcher.changed.notify_all();
    }
}

enum Hop {
    Image(DownloadedImage),
    Redirect(String),
}

impl ImageFetcher {
    pub fn new(config: FetcherConfig) -> Self {
        Self {
            download_slots: Semaphore::new(config.max_concurrent_downloads),
            dns_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_DOWNLOADS)),
            config,
            state: Mutex::new(CacheState::default()),
            changed: Condvar::new(),
        }
    }

    pub fn config(&self) -> &FetcherConfig {
        &self.config
    }

    fn lock(&self) -> MutexGuard<'_, CacheState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `fetch_image(url, retry=...)`: download an authorized public image,
    /// reusing successes and short-lived failures.
    ///
    /// `retry` bypasses a cached failure after the user clicks Allow
    /// Download. It never relaxes network/type limits, and successful images
    /// are not downloaded again.
    pub fn fetch(&self, url: &str, retry: bool) -> Result<DownloadedImage> {
        let key = target(url)?.url;
        let deadline = Instant::now() + self.config.download_timeout;
        if let Some(entry) = self.lock().cached(&key) {
            if entry.image.is_some() || !retry {
                return entry.result();
            }
        }
        if !self.download_slots.acquire_timeout(remaining(deadline)?) {
            return Err(ImageDownloadError::new(
                "Image downloads are busy. Please try again.",
            ));
        }
        let mut slot = SlotGuard(Some(&self.download_slots));
        let (waiting, id, generation) = {
            let mut state = self.lock();
            if let Some(entry) = state.cached(&key) {
                if entry.image.is_some() || !retry {
                    return entry.result();
                }
            }
            match state.pending.get(&key) {
                Some(id) => (true, *id, 0),
                None => {
                    state.next_pending += 1;
                    let id = state.next_pending;
                    state.pending.insert(key.clone(), id);
                    (false, id, state.generation)
                }
            }
        };
        if waiting {
            slot.release();
            let mut state = self.lock();
            while state.pending.get(&key) == Some(&id) {
                let wait = remaining(deadline)?;
                let (guard, result) = self
                    .changed
                    .wait_timeout(state, wait)
                    .unwrap_or_else(|e| e.into_inner());
                state = guard;
                if result.timed_out() && state.pending.get(&key) == Some(&id) {
                    return Err(ImageDownloadError::new(TIMED_OUT));
                }
            }
            return match state.cached(&key) {
                Some(entry) => entry.result(),
                None => Err(ImageDownloadError::new(
                    "The image download failed. Please try again.",
                )),
            };
        }
        let _pending = PendingGuard {
            fetcher: self,
            key: key.clone(),
            id,
        };
        let outcome = self.download(&key, deadline);
        let mut state = self.lock();
        if generation == state.generation {
            let entry = match &outcome {
                Ok(image) => CacheEntry {
                    image: Some(image.clone()),
                    error: None,
                    expires: Instant::now() + self.config.cache_success,
                },
                Err(error) => CacheEntry {
                    image: None,
                    error: Some(error.0.clone()),
                    expires: Instant::now() + self.config.cache_failure,
                },
            };
            state.remember(&key, entry, &self.config);
        }
        drop(state);
        outcome
    }

    /// `clear_cache`: discard cached image bytes and failures; downloads in
    /// flight will not repopulate the cache.
    pub fn clear_cache(&self) {
        let mut state = self.lock();
        state.generation += 1;
        state.entries.clear();
        state.bytes = 0;
    }

    /// Cached entries (`len(_cache)`).
    #[doc(hidden)]
    pub fn cache_len(&self) -> usize {
        self.lock().entries.len()
    }

    /// Cached image bytes (`_cache_bytes`).
    #[doc(hidden)]
    pub fn cache_bytes(&self) -> usize {
        self.lock().bytes
    }

    /// Downloads in flight (`len(_pending)`).
    #[doc(hidden)]
    pub fn pending_len(&self) -> usize {
        self.lock().pending.len()
    }

    /// Whether the canonical `url` has a cache entry (`url in _cache`).
    #[doc(hidden)]
    pub fn cache_contains(&self, url: &str) -> bool {
        self.lock().entries.iter().any(|(key, _)| key == url)
    }

    /// Make the cache entry for canonical `url` expire now (tests: Python
    /// replaced the entry with `expires=0`).
    #[doc(hidden)]
    pub fn expire_cache_entry(&self, url: &str) {
        let now = Instant::now();
        for (key, entry) in self.lock().entries.iter_mut() {
            if key == url {
                entry.expires = now;
            }
        }
    }

    /// `_resolve`: vetted addresses for `target`.
    fn resolve(&self, target: &Target, deadline: Instant) -> Result<Vec<SocketAddr>> {
        let lookup: Option<Arc<LookupFn>> = match &self.config.resolver {
            Resolver::UnvettedForTests(resolve) => match resolve(target) {
                Some(records) => return Ok(records),
                None => None,
            },
            Resolver::Lookup(lookup) => Some(lookup.clone()),
            Resolver::System => None,
        };
        let records = match ip::parse_ip(&target.host) {
            Some((address, _)) => vec![SocketAddr::new(address, target.port)],
            None => self.lookup(target, lookup, deadline)?,
        };
        // Reject mixed public/private DNS results, rather than silently
        // accepting the public part of a response controlled by a sender.
        vet_records(&records)?;
        Ok(records)
    }

    /// `socket.getaddrinfo` on a bounded worker thread, abandoned (not
    /// awaited) at the deadline.
    fn lookup(
        &self,
        target: &Target,
        lookup: Option<Arc<LookupFn>>,
        deadline: Instant,
    ) -> Result<Vec<SocketAddr>> {
        if !self.dns_slots.acquire_timeout(remaining(deadline)?) {
            return Err(ImageDownloadError::new(TIMED_OUT));
        }
        let (sender, receiver) = mpsc::channel();
        let slots = self.dns_slots.clone();
        let host = target.host.clone();
        let port = target.port;
        let spawned = std::thread::Builder::new()
            .name("email-image-dns".into())
            .spawn(move || {
                let result = match lookup {
                    Some(lookup) => lookup(&host, port),
                    None => (host.as_str(), port)
                        .to_socket_addrs()
                        .map(|records| records.collect()),
                };
                slots.release();
                let _ = sender.send(result);
            });
        if spawned.is_err() {
            self.dns_slots.release();
            return Err(ImageDownloadError::new(UNREACHABLE));
        }
        match receiver.recv_timeout(remaining(deadline)?) {
            Ok(Ok(records)) => Ok(records),
            Ok(Err(_)) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err(ImageDownloadError::new(UNREACHABLE))
            }
            Err(mpsc::RecvTimeoutError::Timeout) => Err(ImageDownloadError::new(TIMED_OUT)),
        }
    }

    /// `_PinnedConnection.connect`: the exact checked addresses, in order; no
    /// second hostname lookup. HTTPS verifies the original hostname.
    fn connect(
        &self,
        target: &Target,
        records: &[SocketAddr],
        deadline: Instant,
    ) -> Result<Connection> {
        for address in records {
            let timeout = self.config.socket_timeout.min(remaining(deadline)?);
            let Ok(socket) = TcpStream::connect_timeout(address, timeout) else {
                continue;
            };
            let Ok(handle) = socket.try_clone() else {
                continue;
            };
            let mut connection_socket = Some(socket);
            let stream = if target.scheme == "https" {
                let timeout = self.config.socket_timeout.min(remaining(deadline)?);
                let socket = connection_socket.take().expect("socket");
                if socket.set_read_timeout(Some(timeout)).is_err()
                    || socket.set_write_timeout(Some(timeout)).is_err()
                {
                    continue;
                }
                let Ok(connector) = native_tls::TlsConnector::new() else {
                    continue;
                };
                match connector.connect(&target.host, socket) {
                    Ok(stream) => Stream::Tls(Box::new(stream)),
                    Err(_) => continue,
                }
            } else {
                Stream::Plain(connection_socket.take().expect("socket"))
            };
            let connection = Connection::new(stream, handle, deadline);
            if connection.set_timeout(timeout).is_err() {
                continue;
            }
            return Ok(connection);
        }
        Err(ImageDownloadError::new(UNREACHABLE))
    }

    /// `_download`: follow up to [`MAX_REDIRECTS`] redirects, validating and
    /// resolving every hop.
    fn download(&self, url: &str, deadline: Instant) -> Result<DownloadedImage> {
        let mut current = url.to_string();
        for redirect in 0..=MAX_REDIRECTS {
            let target = target(&current)?;
            let records = self.resolve(&target, deadline)?;
            let mut connection = self.connect(&target, &records, deadline)?;
            match self.exchange(
                &target,
                &mut connection,
                deadline,
                redirect == MAX_REDIRECTS,
            )? {
                Hop::Image(image) => return Ok(image),
                Hop::Redirect(next) => current = next,
            }
            // The connection (and its socket) is closed here, before the
            // next hop connects.
        }
        Err(ImageDownloadError::new(TOO_MANY_REDIRECTS))
    }

    /// One request/response on a fresh single-use connection.
    fn exchange(
        &self,
        target: &Target,
        connection: &mut Connection,
        deadline: Instant,
        last_hop: bool,
    ) -> Result<Hop> {
        let request =
            http::request_bytes(&target.host, target.port, &target.path, &request_headers()?);
        connection.send(&request)?;
        connection.set_timeout(self.config.socket_timeout.min(remaining(deadline)?))?;
        // An inactivity timeout alone does not bound a server trickling
        // response headers/body: interrupt even a blocking read at the
        // total deadline.
        let _watchdog = Watchdog::start(connection.socket(), remaining(deadline)?);
        let mut response = Response::begin(connection)?;
        if matches!(response.status, 301 | 302 | 303 | 307 | 308) {
            let location = response.headers.getheader("Location").unwrap_or_default();
            if location.is_empty() || last_hop {
                return Err(ImageDownloadError::new(TOO_MANY_REDIRECTS));
            }
            return Ok(Hop::Redirect(redirect_url(&target.url, &location)?));
        }
        if response.status != 200 {
            return Err(ImageDownloadError::new(
                "The image server did not provide the image.",
            ));
        }
        let encoding = response
            .headers
            .getheader("Content-Encoding")
            .unwrap_or_else(|| "identity".to_string())
            .to_lowercase();
        if !(encoding.is_empty() || encoding == "identity") {
            return Err(ImageDownloadError::new(
                "Compressed image responses are not permitted.",
            ));
        }
        let max = self.config.max_image_bytes;
        let declared_length = match response.headers.getheader("Content-Length") {
            Some(value) => match http::py_int(&value, 10) {
                Some(length) if length > 0 && length <= max as i128 => Some(length as usize),
                _ => return Err(ImageDownloadError::new("The image size is not permitted.")),
            },
            None => None,
        };
        let mut content: Vec<u8> = Vec::new();
        loop {
            connection.set_timeout(self.config.socket_timeout.min(remaining(deadline)?))?;
            let chunk = response.read1(connection, 65536.min(max + 1 - content.len()))?;
            remaining(deadline)?;
            if chunk.is_empty() {
                break;
            }
            content.extend_from_slice(&chunk);
            if content.len() > max {
                return Err(ImageDownloadError::new("The image is too large."));
            }
        }
        if declared_length.is_some_and(|length| length != content.len()) {
            return Err(ImageDownloadError::new(
                "The image download was incomplete.",
            ));
        }
        let content_type = image_type(&content)?;
        let declared = response
            .headers
            .getheader("Content-Type")
            .unwrap_or_default();
        let declared =
            crate::image_sources::urllib::py_strip(declared.split(';').next().unwrap_or_default())
                .to_lowercase();
        let alias = match declared.as_str() {
            "image/jpg" | "image/pjpeg" => "image/jpeg",
            "image/x-png" => "image/png",
            "image/x-ms-bmp" => "image/bmp",
            other => other,
        };
        if !declared.is_empty() && declared != "application/octet-stream" && alias != content_type {
            return Err(ImageDownloadError::new(
                "The response image type did not match its content.",
            ));
        }
        Ok(Hop::Image(DownloadedImage {
            content,
            content_type: content_type.to_string(),
        }))
    }
}

// ---------------------------------------------------------------------------
// Process-wide fetcher
// ---------------------------------------------------------------------------

static GLOBAL: LazyLock<RwLock<Arc<ImageFetcher>>> =
    LazyLock::new(|| RwLock::new(Arc::new(ImageFetcher::new(FetcherConfig::default()))));

fn global() -> Arc<ImageFetcher> {
    GLOBAL.read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// `fetch_image(url, retry=False)`.
pub fn fetch_image(url: &str, retry: bool) -> Result<DownloadedImage> {
    global().fetch(url, retry)
}

/// Drop every cached image (`clear_cache`).
pub fn clear_cache() {
    global().clear_cache()
}

/// Debug builds only: replace the process-wide fetcher (route tests point it
/// at local servers); returns the previous one.
#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn replace_global_fetcher_for_tests(fetcher: Arc<ImageFetcher>) -> Arc<ImageFetcher> {
    std::mem::replace(
        &mut *GLOBAL.write().unwrap_or_else(|e| e.into_inner()),
        fetcher,
    )
}

/// The process-wide fetcher (introspection in tests).
#[doc(hidden)]
pub fn global_fetcher() -> Arc<ImageFetcher> {
    global()
}
