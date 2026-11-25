//! RPM epoch, version and release ordering for Fedora advisory applicability.

use std::cmp::Ordering;

use anyhow::{Result, ensure};

// https://rpm.org/docs/6.0.x/man/rpm-version.7
pub(super) fn compare(left: &str, right: &str) -> Result<Ordering> {
    ensure!(
        left.len().saturating_add(right.len()) <= 64 * 1024 - 2,
        "RPM version comparison input exceeds limit"
    );
    ensure!(
        [left, right]
            .into_iter()
            .all(|value| !value.is_empty() && !value.chars().any(char::is_control)),
        "Invalid RPM version comparison input"
    );
    let (left_epoch, left_version, left_release) = split_evr(left);
    let (right_epoch, right_version, right_release) = split_evr(right);

    Ok(numeric(left_epoch)
        .cmp(&numeric(right_epoch))
        .then_with(|| compare_component(left_version, right_version))
        .then_with(|| match (left_release, right_release) {
            (Some(left), Some(right)) => compare_component(left, right),
            _ => left_release.is_some().cmp(&right_release.is_some()),
        }))
}

fn split_evr(evr: &str) -> (&str, &str, Option<&str>) {
    let (epoch, version_release) = evr
        .split_once(':')
        .filter(|(epoch, _)| epoch.bytes().all(|byte| byte.is_ascii_digit()))
        .unwrap_or(("0", evr));
    let (version, release) = version_release
        .rsplit_once('-')
        .map_or((version_release, None), |(version, release)| {
            (version, Some(release))
        });
    (epoch, version, release)
}

fn numeric(digits: &str) -> (usize, &str) {
    let significant = digits.trim_start_matches('0');
    (significant.len(), significant)
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Segment<'a> {
    Tilde,
    End,
    Caret,
    Letters(&'a str),
    Digits(usize, &'a str),
}

fn next_segment<'a>(input: &mut &'a str) -> Segment<'a> {
    let remaining = input
        .trim_start_matches(|ch: char| !ch.is_ascii_alphanumeric() && !matches!(ch, '~' | '^'));
    match remaining.as_bytes().first() {
        Some(b'~') => {
            *input = &remaining[1..];
            Segment::Tilde
        }
        Some(b'^') => {
            *input = &remaining[1..];
            Segment::Caret
        }
        Some(b'0'..=b'9') => {
            let length = remaining.bytes().take_while(u8::is_ascii_digit).count();
            let (digits, rest) = remaining.split_at(length);
            *input = rest;
            let (length, significant) = numeric(digits);
            Segment::Digits(length, significant)
        }
        Some(_) => {
            let length = remaining
                .bytes()
                .take_while(u8::is_ascii_alphabetic)
                .count();
            let (letters, rest) = remaining.split_at(length);
            *input = rest;
            Segment::Letters(letters)
        }
        None => {
            *input = "";
            Segment::End
        }
    }
}

fn compare_component(mut left: &str, mut right: &str) -> Ordering {
    if left == right {
        return Ordering::Equal;
    }
    loop {
        let left_segment = next_segment(&mut left);
        let right_segment = next_segment(&mut right);
        let ordering = left_segment.cmp(&right_segment);
        if ordering != Ordering::Equal || left_segment == Segment::End {
            return ordering;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orders_full_rpm_versions_without_external_commands() -> Result<()> {
        let ordered = [
            ("1:9.9-9.fc44", "2:1.0-1.fc44"),
            ("1.0~rc1-1.fc44", "1.0-1.fc44"),
            ("1.0", "1.0^git1"),
            ("1.0^git1-1.fc44", "1.0.1-1.fc44"),
            ("1.0", "1.0-0"),
            ("1.0-9", "1.0-10"),
            ("1.0a", "1.0.0"),
            ("1.0A", "1.0a"),
            ("1.0~rc1^b", "1.0~rc1.1"),
            ("1.0^git1~rc1", "1.0^git1"),
            ("1.0.999999999999999999999", "1.0.1000000000000000000000"),
        ];
        for (older, newer) in ordered {
            assert_eq!(compare(older, newer)?, Ordering::Less, "{older}, {newer}");
            assert_eq!(
                compare(newer, older)?,
                Ordering::Greater,
                "{newer}, {older}"
            );
        }
        for (left, right) in [
            ("1.0-1.fc44", "0:1.0-1.fc44"),
            ("0001:1.0-1.fc44", "1:1.0-1.fc44"),
            ("1+.+0-1", "1.0-01"),
            ("1.0.α", "1.0.ββ"),
            ("1.0+", "1.0"),
            ("1a0001", "1.a.1"),
        ] {
            assert_eq!(compare(left, right)?, Ordering::Equal, "{left}, {right}");
        }
        for bad in ["", "1.0\n2.0", "1.0\0", "1.0\t", "1.0\u{0085}"] {
            assert!(compare(bad, "2.0").is_err(), "{bad:?}");
            assert!(compare("2.0", bad).is_err(), "{bad:?}");
        }
        assert!(compare(&"1".repeat(64 * 1024), "2").is_err());
        Ok(())
    }
}
