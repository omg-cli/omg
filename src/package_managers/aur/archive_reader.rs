//! Bounded package decompression shared by admission and identity checks.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Seek};

use anyhow::{Context, Result};

use crate::runtimes::common::{BudgetedReader, BudgetedWriter, decode_xz_to};

/// Bound work from empty frames independently of decompressed-byte limits.
const MAX_ZSTD_FRAMES: usize = 100_000;

/// ruzstd's StreamingDecoder stops after one frame. Keep its buffered source
/// across frame boundaries so archive inspection matches native libarchive.
struct ZstdFrames<R: BufRead> {
    decoder: Option<ruzstd::decoding::StreamingDecoder<R, ruzstd::decoding::FrameDecoder>>,
    finished: bool,
    frames: usize,
}

impl<R: BufRead> ZstdFrames<R> {
    fn new(source: R) -> io::Result<Self> {
        Ok(Self {
            decoder: Some(
                ruzstd::decoding::StreamingDecoder::new(source).map_err(io::Error::other)?,
            ),
            finished: false,
            frames: 1,
        })
    }
}

impl<R: BufRead> Read for ZstdFrames<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.finished {
            return Ok(0);
        }
        loop {
            let decoder = self
                .decoder
                .as_mut()
                .ok_or_else(|| io::Error::other("Invalid zstd frame state"))?;
            let count = decoder.read(output)?;
            if count != 0 {
                return Ok(count);
            }
            let mut source = self
                .decoder
                .take()
                .ok_or_else(|| io::Error::other("Missing zstd frame"))?
                .into_inner();
            if source.fill_buf()?.is_empty() {
                self.finished = true;
                return Ok(0);
            }
            self.frames += 1;
            if self.frames > MAX_ZSTD_FRAMES {
                return Err(io::Error::other("AUR archive has too many zstd frames"));
            }
            self.decoder =
                Some(ruzstd::decoding::StreamingDecoder::new(source).map_err(io::Error::other)?);
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

    #[test]
    fn empty_reads_preserve_data_and_repeated_eof_reads_stay_empty() -> Result<()> {
        let marker = b"inert marker";
        let compressed = zstd::stream::encode_all(marker.as_slice(), 1)?;
        let mut reader = ZstdFrames::new(BufReader::new(Cursor::new(compressed)))?;
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
            let mut reader = ZstdFrames::new(BufReader::new(Cursor::new(frame.repeat(count))))?;
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
            }
        }
        Ok(())
    }
}
