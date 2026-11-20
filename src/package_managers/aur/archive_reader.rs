//! Bounded package decompression shared by admission and identity checks.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Seek};

use anyhow::{Context, Result};

use crate::runtimes::common::{BudgetedReader, BudgetedWriter, decode_xz_to};

/// Bound work from empty frames independently of decompressed-byte limits.
const MAX_ZSTD_FRAMES: usize = 100_000;

/// ruzstd's StreamingDecoder stops after one frame. Keep its buffered source
/// across frame boundaries so archive inspection matches native libarchive.
enum ZstdState<R: BufRead> {
    Active(Box<ruzstd::decoding::StreamingDecoder<R, ruzstd::decoding::FrameDecoder>>),
    Finished,
    Failed,
}

struct ZstdFrames<R: BufRead> {
    state: ZstdState<R>,
    frames: usize,
}

impl<R: BufRead> ZstdFrames<R> {
    fn new(source: R) -> io::Result<Self> {
        Ok(Self {
            state: ZstdState::Active(Box::new(
                ruzstd::decoding::StreamingDecoder::new(source).map_err(io::Error::other)?,
            )),
            frames: 1,
        })
    }
}

impl<R: BufRead> Read for ZstdFrames<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        loop {
            let mut decoder = match std::mem::replace(&mut self.state, ZstdState::Failed) {
                ZstdState::Active(decoder) => decoder,
                ZstdState::Finished => {
                    self.state = ZstdState::Finished;
                    return Ok(0);
                }
                ZstdState::Failed => return Err(io::Error::other("Invalid zstd frame state")),
            };
            match decoder.read(output) {
                Ok(0) => {}
                result => {
                    self.state = ZstdState::Active(decoder);
                    return result;
                }
            }
            match decoder.get_mut().fill_buf() {
                Ok([]) => {
                    self.state = ZstdState::Finished;
                    return Ok(0);
                }
                Ok(_) => {}
                Err(error) => {
                    self.state = ZstdState::Active(decoder);
                    return Err(error);
                }
            }
            if self.frames >= MAX_ZSTD_FRAMES {
                return Err(io::Error::other("AUR archive has too many zstd frames"));
            }
            let decoder = ruzstd::decoding::StreamingDecoder::new(decoder.into_inner())
                .map_err(io::Error::other)?;
            self.frames += 1;
            self.state = ZstdState::Active(Box::new(decoder));
        }
    }
}

pub(super) fn decode(mut file: File, limit: u64) -> Result<Box<dyn Read>> {
    let mut magic = [0_u8; 6];
    let length = file.read(&mut magic)?;
    file.rewind()?;
    let magic = &magic[..length];
    if magic.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        Ok(Box::new(BudgetedReader::new(
            ZstdFrames::new(BufReader::new(file))?,
            limit,
        )))
    } else if magic.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
        let temporary = tempfile::tempfile()?;
        let mut output = BudgetedWriter::new(std::io::BufWriter::new(temporary), limit);
        decode_xz_to(BufReader::new(file), &mut output)
            .context("Invalid, corrupt or oversized xz AUR archive")?;
        let mut output = output.into_inner().into_inner()?;
        output.rewind()?;
        Ok(Box::new(output))
    } else if magic.starts_with(&[0x1f, 0x8b]) {
        Ok(Box::new(BudgetedReader::new(
            flate2::read::MultiGzDecoder::new(file),
            limit,
        )))
    } else {
        Ok(Box::new(BudgetedReader::new(file, limit)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct BoundaryErrorReader {
        bytes: Cursor<Vec<u8>>,
        boundary: u64,
        error: Option<io::ErrorKind>,
    }

    impl BoundaryErrorReader {
        fn uninterrupted(bytes: Vec<u8>) -> Self {
            Self {
                bytes: Cursor::new(bytes),
                boundary: 0,
                error: None,
            }
        }
    }

    impl Read for BoundaryErrorReader {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let source = self.bytes.fill_buf()?;
            let count = source.len().min(output.len());
            output[..count].copy_from_slice(&source[..count]);
            self.consume(count);
            Ok(count)
        }
    }

    impl BufRead for BoundaryErrorReader {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            if self.bytes.position() == self.boundary
                && let Some(kind) = self.error.take()
            {
                return Err(io::Error::from(kind));
            }
            self.bytes.fill_buf()
        }

        fn consume(&mut self, amount: usize) {
            self.bytes.consume(amount);
        }
    }

    #[test]
    fn boundary_errors_can_be_retried_for_next_frame_and_eof() -> Result<()> {
        for kind in [io::ErrorKind::Interrupted, io::ErrorKind::WouldBlock] {
            for next_frame in [false, true] {
                let first = zstd::stream::encode_all(b"first".as_slice(), 1)?;
                let boundary = first.len() as u64;
                let mut bytes = first;
                if next_frame {
                    bytes.extend(zstd::stream::encode_all(b"second".as_slice(), 1)?);
                }
                let source = BoundaryErrorReader {
                    bytes: Cursor::new(bytes),
                    boundary,
                    error: Some(kind),
                };
                let mut reader = ZstdFrames::new(source)?;
                let mut first_output = [0; 5];
                reader.read_exact(&mut first_output)?;
                assert_eq!(&first_output, b"first");
                let mut output = [0; 16];
                assert_eq!(
                    reader.read(&mut output).expect_err("boundary error").kind(),
                    kind
                );
                let mut remaining = Vec::new();
                reader.read_to_end(&mut remaining)?;
                assert_eq!(
                    remaining,
                    if next_frame {
                        b"second".as_slice()
                    } else {
                        b""
                    }
                );
                assert_eq!(reader.read(&mut output)?, 0);
            }
        }
        Ok(())
    }

    #[test]
    fn invalid_next_frame_remains_failed_after_empty_reads() -> Result<()> {
        let mut bytes = zstd::stream::encode_all(b"first".as_slice(), 1)?;
        bytes.extend_from_slice(b"invalid frame");
        let mut reader = ZstdFrames::new(BoundaryErrorReader::uninterrupted(bytes))?;
        let mut first = [0; 5];
        reader.read_exact(&mut first)?;
        assert_eq!(&first, b"first");
        assert!(reader.read(&mut [0; 1]).is_err());
        assert_eq!(reader.read(&mut [])?, 0);
        assert!(reader.read(&mut [0; 1]).is_err());
        Ok(())
    }

    #[test]
    fn empty_reads_preserve_data_and_repeated_eof_reads_stay_empty() -> Result<()> {
        let marker = b"inert marker";
        let compressed = zstd::stream::encode_all(marker.as_slice(), 1)?;
        let mut reader = ZstdFrames::new(BoundaryErrorReader::uninterrupted(compressed))?;
        assert_eq!(reader.read(&mut [])?, 0);
        let mut output = Vec::new();
        reader.read_to_end(&mut output)?;
        assert_eq!(output, marker);
        assert_eq!(reader.read(&mut [0; 1])?, 0);
        assert_eq!(reader.read(&mut [])?, 0);
        Ok(())
    }

    #[test]
    fn empty_zstd_frames_are_bounded_even_without_expanded_bytes() -> Result<()> {
        let frame = zstd::stream::encode_all(std::io::empty(), 1)?;
        for count in [MAX_ZSTD_FRAMES, MAX_ZSTD_FRAMES + 1] {
            let mut reader =
                ZstdFrames::new(BoundaryErrorReader::uninterrupted(frame.repeat(count)))?;
            let mut output = Vec::new();
            let result = reader.read_to_end(&mut output);
            assert!(output.is_empty(), "empty frames must not create output");
            if count == MAX_ZSTD_FRAMES {
                assert_eq!(result?, 0);
            } else {
                let error = result.expect_err("excess empty frames must be refused");
                assert!(
                    error.to_string().contains("too many zstd frames"),
                    "{error}"
                );
                assert_eq!(reader.read(&mut [])?, 0);
                assert!(reader.read(&mut [0; 1]).is_err());
            }
        }
        Ok(())
    }
}
