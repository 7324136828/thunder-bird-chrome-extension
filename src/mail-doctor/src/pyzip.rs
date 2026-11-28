//! A ZIP reader that follows CPython's `zipfile` (3.12 reading code, plus the
//! Zstandard method of 3.14) for `temp_manager.prepare_inputs`.
//!
//! The `zip` crate is not used for reading uploads because it differs from
//! `zipfile` where it matters for the audit:
//!
//! * it keys entries by name, so an archive with two `x.eml` entries exposes
//!   only one, while `zipfile.infolist()` lists both (`prepare_inputs` then
//!   extracts `x.eml` and `x_1.eml` and counts both toward the member cap);
//! * its LZMA (method 14) reader expects an `.lzma` header with an
//!   uncompressed size and cannot decode the ZIP LZMA layout
//!   (`version, props_size, props`) that `zipfile` reads and writes.
//!
//! What is reproduced: end-of-central-directory search (with archive
//! comments, ZIP64 records and prepended data, the `concat` offset), the
//! central directory walk (`cp437`/UTF-8 names, NUL truncation, the ZIP64 and
//! Info-ZIP Unicode Path (0x7075) extra fields, `extract_version > 63`), the
//! checks of `ZipFile.open` (local header magic, flag bits 5/6, the name in
//! the local header, overlapped entries), and `ZipExtFile` reading: the
//! stored, deflate, bzip2, LZMA and Zstandard methods (others are "not
//! supported"), output truncated to `file_size`, and the CRC-32 checked when
//! the member ends.
//!
//! Residual differences, all for corrupt archives: Python raises
//! `zlib.error`, `OSError` (bzip2), `LZMAError`, `EOFError` (truncated data)
//! or `UnicodeDecodeError` (invalid UTF-8 names), which `prepare_inputs` does
//! not translate, so the job fails with that exception text; here they are
//! all [`PyZipError::BadZipFile`] ("Cannot read the uploaded ZIP archive").
//! An LZMA stream whose end marker comes before `file_size` bytes fails here
//! even when the shorter output matches the stored CRC.

use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};

/// `sizeEndCentDir`, `sizeCentralDir`, `sizeFileHeader`, ZIP64 record sizes.
const END_CENT_DIR: usize = 22;
const END_CENT_DIR64: u64 = 56;
const END_CENT_DIR64_LOCATOR: u64 = 20;
const CENTRAL_DIR: usize = 46;
const FILE_HEADER: usize = 30;
const MAX_COMMENT: u64 = (1 << 16) - 1;
/// `MAX_EXTRACT_VERSION`.
const MAX_EXTRACT_VERSION: u8 = 63;
/// `_MASK_*` flag bits.
const MASK_COMPRESSED_PATCH: u16 = 1 << 5;
const MASK_STRONG_ENCRYPTION: u16 = 1 << 6;
const MASK_UTF_FILENAME: u16 = 1 << 11;
/// Compression methods `zipfile` can read (3.14: `ZIP_ZSTANDARD`).
pub const ZIP_STORED: u16 = 0;
pub const ZIP_DEFLATED: u16 = 8;
pub const ZIP_BZIP2: u16 = 12;
pub const ZIP_LZMA: u16 = 14;
pub const ZIP_ZSTANDARD: u16 = 93;
/// Bytes read per decoder call (`zipfile` reads members in 1 MiB chunks in
/// `prepare_inputs`).
const CHUNK: usize = 1024 * 1024;

/// `zipfile.BadZipFile`, or the `RuntimeError` / `NotImplementedError`
/// `zipfile` raises for unsupported features; `Io` is an `OSError` reading
/// the archive file itself.
#[derive(Debug, thiserror::Error)]
pub enum PyZipError {
    #[error("{0}")]
    BadZipFile(String),
    #[error("{0}")]
    NotImplemented(String),
    #[error(transparent)]
    Io(#[from] io::Error),
}

fn bad(message: impl Into<String>) -> PyZipError {
    PyZipError::BadZipFile(message.into())
}

/// The failure of [`ZipFile::extract`]: the archive, or the chunk callback.
#[derive(Debug)]
pub enum ExtractError<E> {
    Zip(PyZipError),
    Sink(E),
}

impl<E> From<PyZipError> for ExtractError<E> {
    fn from(error: PyZipError) -> Self {
        Self::Zip(error)
    }
}

/// The fields of `zipfile.ZipInfo` that reading uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZipInfo {
    /// The decoded name as stored in the central directory.
    pub orig_filename: String,
    /// `_sanitize_filename(orig_filename)` (cut at the first NUL), or the
    /// Info-ZIP Unicode Path when it matches the stored name. Unlike Python
    /// on Windows, `\` is left as is (callers normalize it).
    pub filename: String,
    pub flag_bits: u16,
    pub compress_type: u16,
    pub crc: u32,
    pub compress_size: u64,
    pub file_size: u64,
    pub header_offset: u64,
    pub external_attr: u32,
    /// Start of the next local header or of the central directory.
    end_offset: u64,
}

impl ZipInfo {
    /// `ZipInfo.is_dir()` (POSIX form: a trailing `/`).
    pub fn is_dir(&self) -> bool {
        self.filename.ends_with('/')
    }
}

/// `zipfile.ZipFile(path, "r")` over a seekable reader.
pub struct ZipFile<R> {
    reader: BufReader<R>,
    infolist: Vec<ZipInfo>,
}

fn u16_at(data: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([data[at], data[at + 1]])
}

fn u32_at(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
}

fn u64_at(data: &[u8], at: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&data[at..at + 8]);
    u64::from_le_bytes(bytes)
}

/// `fp.read(n)`: up to `n` bytes, fewer at the end of the file.
fn read_up_to<R: Read>(reader: &mut R, n: u64) -> io::Result<Vec<u8>> {
    let mut data = Vec::new();
    reader.take(n).read_to_end(&mut data)?;
    Ok(data)
}

/// `bytes.decode("cp437")`.
pub fn decode_cp437(raw: &[u8]) -> String {
    const HIGH: &str = "ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■\u{a0}";
    raw.iter()
        .map(|&byte| {
            if byte < 0x80 {
                byte as char
            } else {
                HIGH.chars().nth(usize::from(byte - 0x80)).unwrap_or('?')
            }
        })
        .collect()
}

/// The member name decoding of `_RealGetContents` / `ZipFile.open`.
fn decode_name(raw: &[u8], flags: u16) -> Result<String, PyZipError> {
    if flags & MASK_UTF_FILENAME != 0 {
        String::from_utf8(raw.to_vec()).map_err(|_| bad("invalid UTF-8 file name"))
    } else {
        Ok(decode_cp437(raw))
    }
}

/// `_sanitize_filename` without the Windows `os.sep` replacement.
fn sanitize_filename(name: &str) -> String {
    name.split('\0').next().unwrap_or_default().to_string()
}

/// The end-of-central-directory fields `_RealGetContents` uses.
struct EndRecord {
    zip64: bool,
    size_cd: u64,
    offset_cd: u64,
    location: u64,
}

/// `_EndRecData` + `_EndRecData64`.
fn end_record<R: Read + Seek>(reader: &mut R) -> Result<Option<EndRecord>, PyZipError> {
    let filesize = reader.seek(SeekFrom::End(0))?;
    if filesize < END_CENT_DIR as u64 {
        return Ok(None);
    }
    reader.seek(SeekFrom::Start(filesize - END_CENT_DIR as u64))?;
    let data = read_up_to(reader, END_CENT_DIR as u64)?;
    let (record, location) = if data.len() == END_CENT_DIR
        && data[..4] == *b"PK\x05\x06"
        && data[END_CENT_DIR - 2..] == [0, 0]
    {
        (data, filesize - END_CENT_DIR as u64)
    } else {
        let start = filesize.saturating_sub(MAX_COMMENT + END_CENT_DIR as u64);
        reader.seek(SeekFrom::Start(start))?;
        let data = read_up_to(reader, MAX_COMMENT + END_CENT_DIR as u64)?;
        let Some(found) = data.windows(4).rposition(|window| window == b"PK\x05\x06") else {
            return Ok(None);
        };
        if data.len() - found < END_CENT_DIR {
            return Ok(None);
        }
        (
            data[found..found + END_CENT_DIR].to_vec(),
            start + found as u64,
        )
    };
    let mut end = EndRecord {
        zip64: false,
        size_cd: u64::from(u32_at(&record, 12)),
        offset_cd: u64::from(u32_at(&record, 16)),
        location,
    };
    // `_EndRecData64`: the locator sits right before the end record.
    let Some(locator_at) = location.checked_sub(END_CENT_DIR64_LOCATOR) else {
        return Ok(Some(end));
    };
    reader.seek(SeekFrom::Start(locator_at))?;
    let locator = read_up_to(reader, END_CENT_DIR64_LOCATOR)?;
    if locator.len() != END_CENT_DIR64_LOCATOR as usize || locator[..4] != *b"PK\x06\x07" {
        return Ok(Some(end));
    }
    if u32_at(&locator, 4) != 0 || u32_at(&locator, 16) > 1 {
        return Err(bad("zipfiles that span multiple disks are not supported"));
    }
    let Some(record_at) = locator_at.checked_sub(END_CENT_DIR64) else {
        return Ok(Some(end));
    };
    reader.seek(SeekFrom::Start(record_at))?;
    let record = read_up_to(reader, END_CENT_DIR64)?;
    if record.len() != END_CENT_DIR64 as usize || record[..4] != *b"PK\x06\x06" {
        return Ok(Some(end));
    }
    end.zip64 = true;
    end.size_cd = u64_at(&record, 40);
    end.offset_cd = u64_at(&record, 48);
    Ok(Some(end))
}

/// `ZipInfo._decodeExtra`: ZIP64 sizes/offset and the Unicode Path field.
fn decode_extra(info: &mut ZipInfo, extra: &[u8], name_crc: u32) -> Result<(), PyZipError> {
    let mut extra = extra;
    while extra.len() >= 4 {
        let kind = u16_at(extra, 0);
        let len = usize::from(u16_at(extra, 2));
        if len + 4 > extra.len() {
            return Err(bad(format!("Corrupt extra field {kind:04x} (size={len})")));
        }
        let mut data = &extra[4..len + 4];
        if kind == 0x0001 {
            let mut take = |field: &str| -> Result<u64, PyZipError> {
                if data.len() < 8 {
                    return Err(bad(format!(
                        "Corrupt zip64 extra field. {field} not found."
                    )));
                }
                let value = u64_at(data, 0);
                data = &data[8..];
                Ok(value)
            };
            if info.file_size == 0xFFFF_FFFF_FFFF_FFFF || info.file_size == 0xFFFF_FFFF {
                info.file_size = take("File size")?;
            }
            if info.compress_size == 0xFFFF_FFFF {
                info.compress_size = take("Compress size")?;
            }
            if info.header_offset == 0xFFFF_FFFF {
                info.header_offset = take("Header offset")?;
            }
        } else if kind == 0x7075 {
            if data.len() < 5 {
                return Err(bad("Corrupt unicode path extra field (0x7075)"));
            }
            if data[0] == 1 && u32_at(data, 1) == name_crc {
                let name = std::str::from_utf8(&data[5..]).map_err(|_| {
                    bad("Corrupt unicode path extra field (0x7075): invalid utf-8 bytes")
                })?;
                if !name.is_empty() {
                    info.filename = sanitize_filename(name);
                }
            }
        }
        extra = &extra[len + 4..];
    }
    Ok(())
}

impl<R: Read + Seek> ZipFile<R> {
    /// `ZipFile(file)`: read the whole central directory (`_RealGetContents`).
    pub fn new(reader: R) -> Result<Self, PyZipError> {
        let mut reader = BufReader::new(reader);
        let end = match end_record(&mut reader) {
            Ok(Some(end)) => end,
            Ok(None) | Err(PyZipError::Io(_)) => return Err(bad("File is not a zip file")),
            Err(error) => return Err(error),
        };
        let mut concat = end.location as i128 - end.size_cd as i128 - end.offset_cd as i128;
        if end.zip64 {
            concat -= i128::from(END_CENT_DIR64 + END_CENT_DIR64_LOCATOR);
        }
        let start_dir = end.offset_cd as i128 + concat;
        if start_dir < 0 {
            return Err(bad("Bad offset for central directory"));
        }
        let start_dir = start_dir as u64;
        reader.seek(SeekFrom::Start(start_dir))?;
        let directory = read_up_to(&mut reader, end.size_cd)?;
        let mut infolist = Vec::new();
        let mut at = 0usize;
        while (at as u64) < end.size_cd {
            let Some(header) = directory.get(at..at + CENTRAL_DIR) else {
                return Err(bad("Truncated central directory"));
            };
            if header[..4] != *b"PK\x01\x02" {
                return Err(bad("Bad magic number for central directory"));
            }
            let name_len = usize::from(u16_at(header, 28));
            let extra_len = usize::from(u16_at(header, 30));
            let comment_len = usize::from(u16_at(header, 32));
            let rest = &directory[at + CENTRAL_DIR..];
            // `fp.read(n)` returns what is left of the central directory.
            let raw_name = &rest[..name_len.min(rest.len())];
            let rest = &rest[raw_name.len()..];
            let extra = &rest[..extra_len.min(rest.len())];
            let flags = u16_at(header, 8);
            let extract_version = header[6];
            let orig_filename = decode_name(raw_name, flags)?;
            if extract_version > MAX_EXTRACT_VERSION {
                return Err(PyZipError::NotImplemented(format!(
                    "zip file version {:.1}",
                    f64::from(extract_version) / 10.0
                )));
            }
            let mut info = ZipInfo {
                filename: sanitize_filename(&orig_filename),
                orig_filename,
                flag_bits: flags,
                compress_type: u16_at(header, 10),
                crc: u32_at(header, 16),
                compress_size: u64::from(u32_at(header, 20)),
                file_size: u64::from(u32_at(header, 24)),
                header_offset: u64::from(u32_at(header, 42)),
                external_attr: u32_at(header, 38),
                end_offset: 0,
            };
            decode_extra(&mut info, extra, crc32fast::hash(raw_name))?;
            let offset = info.header_offset as i128 + concat;
            info.header_offset = u64::try_from(offset).unwrap_or(u64::MAX);
            infolist.push(info);
            at += CENTRAL_DIR + name_len + extra_len + comment_len;
        }
        // `_end_offset`: the next local header (by offset) or the directory.
        let mut order: Vec<usize> = (0..infolist.len()).collect();
        order.sort_by_key(|&index| infolist[index].header_offset);
        let mut end_offset = start_dir;
        for &index in order.iter().rev() {
            infolist[index].end_offset = end_offset;
            end_offset = infolist[index].header_offset;
        }
        Ok(Self { reader, infolist })
    }

    /// `ZipFile.infolist()`, duplicates included, in central directory order.
    pub fn infolist(&self) -> &[ZipInfo] {
        &self.infolist
    }

    /// `ZipFile.open(member)` checks; returns the offset of the member data.
    fn open_member(&mut self, index: usize) -> Result<u64, PyZipError> {
        let info = &self.infolist[index];
        self.reader.seek(SeekFrom::Start(info.header_offset))?;
        let header = read_up_to(&mut self.reader, FILE_HEADER as u64)?;
        if header.len() != FILE_HEADER {
            return Err(bad("Truncated file header"));
        }
        if header[..4] != *b"PK\x03\x04" {
            return Err(bad("Bad magic number for file header"));
        }
        let name_len = u64::from(u16_at(&header, 26));
        let extra_len = u64::from(u16_at(&header, 28));
        let raw_name = read_up_to(&mut self.reader, name_len)?;
        if info.flag_bits & MASK_COMPRESSED_PATCH != 0 {
            return Err(PyZipError::NotImplemented(
                "compressed patched data (flag bit 5)".into(),
            ));
        }
        if info.flag_bits & MASK_STRONG_ENCRYPTION != 0 {
            return Err(PyZipError::NotImplemented(
                "strong encryption (flag bit 6)".into(),
            ));
        }
        if decode_name(&raw_name, u16_at(&header, 6))? != info.orig_filename {
            return Err(bad(format!(
                "File name in directory {:?} and header differ.",
                info.orig_filename
            )));
        }
        let data_start = info.header_offset + FILE_HEADER as u64 + name_len + extra_len;
        // A member whose end offset equals its own header offset (two entries
        // sharing one local header) only warns in Python.
        if data_start.saturating_add(info.compress_size) > info.end_offset
            && info.end_offset != info.header_offset
        {
            return Err(bad(format!(
                "Overlapped entries: {:?} (possible zip bomb)",
                info.orig_filename
            )));
        }
        if !matches!(
            info.compress_type,
            ZIP_STORED | ZIP_DEFLATED | ZIP_BZIP2 | ZIP_LZMA | ZIP_ZSTANDARD
        ) {
            return Err(PyZipError::NotImplemented(
                "That compression method is not supported".into(),
            ));
        }
        Ok(data_start)
    }

    /// `with zipped.open(member) as source: while chunk := source.read(...)`:
    /// decode member `index`, passing the output to `on_chunk` (at most
    /// `file_size` bytes in total), then check the CRC-32. Encrypted members
    /// must be rejected by the caller first (as `prepare_inputs` does).
    pub fn extract<E>(
        &mut self,
        index: usize,
        on_chunk: impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<(), ExtractError<E>> {
        let data_start = self.open_member(index)?;
        let info = self.infolist[index].clone();
        self.reader
            .seek(SeekFrom::Start(data_start))
            .map_err(PyZipError::from)?;
        let compressed = (&mut self.reader).take(info.compress_size);
        let mut sink = MemberSink {
            left: info.file_size,
            crc: crc32fast::Hasher::new(),
            on_chunk,
            failure: None,
        };
        let decoded = match info.compress_type {
            ZIP_STORED => sink.pump(compressed),
            ZIP_DEFLATED => sink.pump(flate2::read::DeflateDecoder::new(compressed)),
            ZIP_BZIP2 => sink.pump(bzip2::read::BzDecoder::new(compressed)),
            ZIP_ZSTANDARD => zstd::stream::read::Decoder::with_buffer(compressed)
                .map(zstd::stream::read::Decoder::single_frame)
                .and_then(|decoder| sink.pump(decoder)),
            ZIP_LZMA => decode_lzma(compressed, info.file_size, &mut sink),
            _ => unreachable!("checked by open_member"),
        };
        if let Some(failure) = sink.failure.take() {
            return Err(ExtractError::Sink(failure));
        }
        decoded.map_err(|_| bad("Cannot decompress the member"))?;
        if sink.crc.finalize() != info.crc {
            return Err(bad(format!("Bad CRC-32 for file {:?}", info.filename)).into());
        }
        Ok(())
    }
}

/// The `ZipExtFile` output side: truncation to `file_size`, the running CRC
/// and the caller's chunk callback (whose error is kept in `failure`).
struct MemberSink<F, E> {
    left: u64,
    crc: crc32fast::Hasher,
    on_chunk: F,
    failure: Option<E>,
}

impl<F: FnMut(&[u8]) -> Result<(), E>, E> MemberSink<F, E> {
    /// Read `decoder` to its end (or until `file_size` bytes were produced).
    fn pump(&mut self, mut decoder: impl Read) -> io::Result<()> {
        let mut buffer = vec![0u8; CHUNK];
        while self.left > 0 {
            let read = match decoder.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            };
            self.write_all(&buffer[..read])?;
        }
        Ok(())
    }
}

impl<F: FnMut(&[u8]) -> Result<(), E>, E> Write for MemberSink<F, E> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        // `data = data[:self._left]`; later output is dropped.
        let keep = data
            .len()
            .min(usize::try_from(self.left).unwrap_or(usize::MAX));
        if keep > 0 {
            self.crc.update(&data[..keep]);
            self.left -= keep as u64;
            if let Err(error) = (self.on_chunk)(&data[..keep]) {
                self.failure = Some(error);
                return Err(io::Error::other("extraction stopped"));
            }
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// `zipfile.LZMADecompressor`: a 4-byte header (version, properties size),
/// the LZMA1 properties, then a raw LZMA1 stream, decoded to `file_size`
/// bytes (or to its end marker).
fn decode_lzma<R: BufRead, F: FnMut(&[u8]) -> Result<(), E>, E>(
    mut compressed: R,
    file_size: u64,
    sink: &mut MemberSink<F, E>,
) -> io::Result<()> {
    let mut header = Vec::with_capacity(4);
    (&mut compressed).take(4).read_to_end(&mut header)?;
    if header.len() < 4 {
        // Python's decompressor waits for more input and yields nothing.
        return Ok(());
    }
    let props_size = u64::from(u16::from_le_bytes([header[2], header[3]]));
    let mut props = Vec::new();
    (&mut compressed).take(props_size).read_to_end(&mut props)?;
    if (props.len() as u64) < props_size {
        return Ok(());
    }
    if props.len() != 5 {
        // `lzma._decode_filter_properties(FILTER_LZMA1, ...)` needs 5 bytes.
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid or unsupported options",
        ));
    }
    let mut compressed = BufReader::new(compressed);
    if compressed.fill_buf()?.is_empty() {
        // Header and properties only: Python's decompressor yields nothing.
        return Ok(());
    }
    let mut input = io::Cursor::new(props).chain(compressed);
    let options = lzma_rs::decompress::Options {
        unpacked_size: lzma_rs::decompress::UnpackedSize::UseProvided(Some(file_size)),
        // The dictionary only grows with the output, which stops at
        // `file_size` (plus at most one match of 273 bytes).
        memlimit: Some(usize::try_from(file_size.saturating_add(1024)).unwrap_or(usize::MAX)),
        allow_incomplete: false,
    };
    lzma_rs::lzma_decompress_with_options(&mut input, sink, &options)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, format!("{error:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One hand-written member: local name, central name, method, data.
    struct Raw<'a> {
        local_name: &'a [u8],
        central_name: &'a [u8],
        flags: u16,
        method: u16,
        data: Vec<u8>,
        crc: u32,
        file_size: u32,
        extra: Vec<u8>,
        /// Use the local header of an earlier member instead of writing one.
        share_header_of: Option<usize>,
    }

    fn raw<'a>(name: &'a [u8], method: u16, data: Vec<u8>, plain: &[u8]) -> Raw<'a> {
        Raw {
            local_name: name,
            central_name: name,
            flags: 0,
            method,
            data,
            crc: crc32fast::hash(plain),
            file_size: plain.len() as u32,
            extra: Vec::new(),
            share_header_of: None,
        }
    }

    fn build(prefix: &[u8], members: &[Raw]) -> Vec<u8> {
        let mut out = prefix.to_vec();
        let mut offsets: Vec<u32> = Vec::new();
        for member in members {
            if let Some(shared) = member.share_header_of {
                offsets.push(offsets[shared]);
                continue;
            }
            offsets.push((out.len() - prefix.len()) as u32);
            out.extend_from_slice(b"PK\x03\x04");
            out.extend_from_slice(&20u16.to_le_bytes());
            out.extend_from_slice(&member.flags.to_le_bytes());
            out.extend_from_slice(&member.method.to_le_bytes());
            out.extend_from_slice(&[0; 4]);
            out.extend_from_slice(&member.crc.to_le_bytes());
            out.extend_from_slice(&(member.data.len() as u32).to_le_bytes());
            out.extend_from_slice(&member.file_size.to_le_bytes());
            out.extend_from_slice(&(member.local_name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(member.local_name);
            out.extend_from_slice(&member.data);
        }
        let directory_start = out.len() - prefix.len();
        for (member, offset) in members.iter().zip(&offsets) {
            out.extend_from_slice(b"PK\x01\x02");
            out.extend_from_slice(&[20, 3, 20, 0]);
            out.extend_from_slice(&member.flags.to_le_bytes());
            out.extend_from_slice(&member.method.to_le_bytes());
            out.extend_from_slice(&[0; 4]);
            out.extend_from_slice(&member.crc.to_le_bytes());
            out.extend_from_slice(&(member.data.len() as u32).to_le_bytes());
            out.extend_from_slice(&member.file_size.to_le_bytes());
            out.extend_from_slice(&(member.central_name.len() as u16).to_le_bytes());
            out.extend_from_slice(&(member.extra.len() as u16).to_le_bytes());
            out.extend_from_slice(&[0; 6]);
            out.extend_from_slice(&(0o100644u32 << 16).to_le_bytes());
            out.extend_from_slice(&offset.to_le_bytes());
            out.extend_from_slice(member.central_name);
            out.extend_from_slice(&member.extra);
        }
        let directory_size = out.len() - prefix.len() - directory_start;
        out.extend_from_slice(b"PK\x05\x06");
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&(members.len() as u16).to_le_bytes());
        out.extend_from_slice(&(members.len() as u16).to_le_bytes());
        out.extend_from_slice(&(directory_size as u32).to_le_bytes());
        out.extend_from_slice(&(directory_start as u32).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    fn read_all(bytes: Vec<u8>) -> Vec<Result<Vec<u8>, String>> {
        let mut zip = ZipFile::new(io::Cursor::new(bytes)).unwrap();
        (0..zip.infolist().len())
            .map(|index| {
                let mut out = Vec::new();
                zip.extract(index, |chunk| -> Result<(), ()> {
                    out.extend_from_slice(chunk);
                    Ok(())
                })
                .map(|()| out)
                .map_err(|error| match error {
                    ExtractError::Zip(error) => error.to_string(),
                    ExtractError::Sink(()) => "sink".into(),
                })
            })
            .collect()
    }

    #[test]
    fn zstandard_members_decode_a_single_frame() {
        let plain = b"From: a@b.example\r\n\r\nzstd body\r\n".repeat(50);
        let frame = zstd::encode_all(&plain[..], 3).unwrap();
        let mut data = frame.clone();
        // A second frame is unused data for `ZstdDecompressor`.
        data.extend_from_slice(&frame);
        let zip = build(b"", &[raw(b"z.eml", ZIP_ZSTANDARD, data, &plain)]);
        assert_eq!(read_all(zip), vec![Ok(plain)]);
    }

    #[test]
    fn output_is_truncated_to_file_size_before_the_crc_check() {
        let member = raw(b"s.eml", ZIP_STORED, b"abcdef".to_vec(), b"abc");
        assert_eq!(read_all(build(b"", &[member])), vec![Ok(b"abc".to_vec())]);
        let member = raw(b"s.eml", ZIP_STORED, b"abcdef".to_vec(), b"abcdeX");
        assert_eq!(
            read_all(build(b"", &[member])),
            vec![Err("Bad CRC-32 for file \"s.eml\"".to_string())]
        );
    }

    #[test]
    fn prepended_data_is_skipped_with_the_concat_offset() {
        let zip = build(
            b"#!/bin/sh\nexit 0\n",
            &[raw(b"a.eml", ZIP_STORED, b"hello".to_vec(), b"hello")],
        );
        assert_eq!(read_all(zip), vec![Ok(b"hello".to_vec())]);
    }

    #[test]
    fn duplicate_names_are_listed_in_central_directory_order() {
        let zip = build(
            b"",
            &[
                raw(b"x.eml", ZIP_STORED, b"one".to_vec(), b"one"),
                raw(b"x.eml", ZIP_STORED, b"two".to_vec(), b"two"),
            ],
        );
        let names: Vec<String> = ZipFile::new(io::Cursor::new(zip.clone()))
            .unwrap()
            .infolist()
            .iter()
            .map(|info| info.filename.clone())
            .collect();
        assert_eq!(names, ["x.eml", "x.eml"]);
        assert_eq!(
            read_all(zip),
            vec![Ok(b"one".to_vec()), Ok(b"two".to_vec())]
        );
    }

    #[test]
    fn open_checks_match_zipfile() {
        let mut renamed = raw(b"a.eml", ZIP_STORED, b"x".to_vec(), b"x");
        renamed.local_name = b"b.eml";
        let mut patched = raw(b"p.eml", ZIP_STORED, b"x".to_vec(), b"x");
        patched.flags = MASK_COMPRESSED_PATCH;
        let deflate64 = raw(b"d.eml", 9, b"x".to_vec(), b"x");
        assert_eq!(
            read_all(build(b"", &[renamed, patched, deflate64])),
            vec![
                Err("File name in directory \"a.eml\" and header differ.".to_string()),
                Err("compressed patched data (flag bit 5)".to_string()),
                Err("That compression method is not supported".to_string()),
            ]
        );
    }

    #[test]
    fn overlapping_members_are_rejected_but_shared_headers_only_warn() {
        let first = raw(b"a.eml", ZIP_STORED, b"abc".to_vec(), b"abc");
        let second = raw(b"b.eml", ZIP_STORED, b"def".to_vec(), b"def");
        let mut zip = build(b"", &[first, second]);
        // `a.eml` claims more data than lies before the next local header.
        let central = zip.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
        zip[central + 20..central + 24].copy_from_slice(&40u32.to_le_bytes());
        let results = read_all(zip);
        assert_eq!(
            results[0],
            Err("Overlapped entries: \"a.eml\" (possible zip bomb)".to_string())
        );
        assert_eq!(results[1], Ok(b"def".to_vec()));

        let mut shared = raw(b"a.eml", ZIP_STORED, b"abc".to_vec(), b"abc");
        shared.share_header_of = Some(0);
        let zip = build(
            b"",
            &[raw(b"a.eml", ZIP_STORED, b"abc".to_vec(), b"abc"), shared],
        );
        assert_eq!(
            read_all(zip),
            vec![Ok(b"abc".to_vec()), Ok(b"abc".to_vec())]
        );
    }

    #[test]
    fn unicode_path_extra_field_renames_matching_entries() {
        let mut member = raw(b"caf\x82.eml", ZIP_STORED, b"x".to_vec(), b"x");
        let name = "renamed\u{e9}.eml".as_bytes();
        let mut extra = vec![0x75, 0x70];
        extra.extend_from_slice(&((5 + name.len()) as u16).to_le_bytes());
        extra.push(1);
        extra.extend_from_slice(&crc32fast::hash(b"caf\x82.eml").to_le_bytes());
        extra.extend_from_slice(name);
        member.extra = extra;
        let zip = ZipFile::new(io::Cursor::new(build(b"", &[member]))).unwrap();
        assert_eq!(zip.infolist()[0].orig_filename, "café.eml");
        assert_eq!(zip.infolist()[0].filename, "renamed\u{e9}.eml");
    }

    #[test]
    fn names_are_cut_at_nul_and_callback_errors_pass_through() {
        let zip = build(b"", &[raw(b"a.eml\0.exe", ZIP_STORED, b"x".to_vec(), b"x")]);
        let mut zip = ZipFile::new(io::Cursor::new(zip)).unwrap();
        assert_eq!(zip.infolist()[0].filename, "a.eml");
        assert_eq!(zip.infolist()[0].orig_filename, "a.eml\0.exe");
        let result = zip.extract(0, |_| Err("stop"));
        assert!(matches!(result, Err(ExtractError::Sink("stop"))));
    }

    #[test]
    fn cp437_names_decode_like_python() {
        assert_eq!(decode_cp437(b"caf\x82.eml"), "café.eml");
        assert_eq!(decode_cp437(b"\xff\x80"), "\u{a0}Ç");
    }

    #[test]
    fn non_zip_input_is_not_a_zip_file() {
        let error = ZipFile::new(io::Cursor::new(b"not a zip".to_vec()))
            .err()
            .unwrap();
        assert!(matches!(error, PyZipError::BadZipFile(m) if m == "File is not a zip file"));
    }
}
