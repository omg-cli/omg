//! Bundled lifecycle dates for OMG-managed runtime release lines.

use anyhow::{Context, Result};
use jiff::{Span, Timestamp, civil::Date, tz::TimeZone};

pub(crate) const SCHEDULE_REVIEWED: &str = "2026-11-26";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SupportStatus {
    Active(&'static str),
    MinimumSupport(&'static str),
    EndingSoon(&'static str),
    Ended(&'static str),
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SupportDate {
    End(&'static str),
    Minimum(&'static str),
}

struct EolEntry {
    runtime: &'static str,
    version_prefix: &'static [u64],
    support: SupportDate,
}

impl EolEntry {
    const fn ends(
        runtime: &'static str,
        version_prefix: &'static [u64],
        date: &'static str,
    ) -> Self {
        Self {
            runtime,
            version_prefix,
            support: SupportDate::End(date),
        }
    }

    const fn minimum(
        runtime: &'static str,
        version_prefix: &'static [u64],
        month: &'static str,
    ) -> Self {
        Self {
            runtime,
            version_prefix,
            support: SupportDate::Minimum(month),
        }
    }
}

const EOL_TABLE: &[EolEntry] = &[
    // https://github.com/nodejs/Release/blob/main/schedule.json
    EolEntry::ends("node", &[0, 8], "2014-07-31"),
    EolEntry::ends("node", &[0, 10], "2016-10-31"),
    EolEntry::ends("node", &[0, 12], "2016-12-31"),
    EolEntry::ends("node", &[4], "2018-04-30"),
    EolEntry::ends("node", &[5], "2016-06-30"),
    EolEntry::ends("node", &[6], "2019-04-30"),
    EolEntry::ends("node", &[7], "2017-06-30"),
    EolEntry::ends("node", &[8], "2019-12-31"),
    EolEntry::ends("node", &[9], "2018-06-30"),
    EolEntry::ends("node", &[10], "2021-04-30"),
    EolEntry::ends("node", &[11], "2019-06-01"),
    EolEntry::ends("node", &[12], "2022-04-30"),
    EolEntry::ends("node", &[13], "2020-06-01"),
    EolEntry::ends("node", &[14], "2023-04-30"),
    EolEntry::ends("node", &[15], "2021-06-01"),
    EolEntry::ends("node", &[16], "2023-09-11"),
    EolEntry::ends("node", &[17], "2022-06-01"),
    EolEntry::ends("node", &[18], "2025-04-30"),
    EolEntry::ends("node", &[19], "2023-06-01"),
    EolEntry::ends("node", &[20], "2026-04-30"),
    EolEntry::ends("node", &[21], "2024-06-01"),
    EolEntry::ends("node", &[22], "2027-04-30"),
    EolEntry::ends("node", &[23], "2025-06-01"),
    EolEntry::ends("node", &[24], "2028-04-30"),
    EolEntry::ends("node", &[25], "2026-06-01"),
    EolEntry::ends("node", &[26], "2029-04-30"),
    // https://devguide.python.org/versions/ (scheduled months use month-end)
    EolEntry::ends("python", &[2, 6], "2013-10-29"),
    EolEntry::ends("python", &[2, 7], "2020-01-01"),
    EolEntry::ends("python", &[3, 0], "2009-06-27"),
    EolEntry::ends("python", &[3, 1], "2012-04-09"),
    EolEntry::ends("python", &[3, 2], "2016-02-20"),
    EolEntry::ends("python", &[3, 3], "2017-09-29"),
    EolEntry::ends("python", &[3, 4], "2019-03-18"),
    EolEntry::ends("python", &[3, 5], "2020-09-30"),
    EolEntry::ends("python", &[3, 6], "2021-12-23"),
    EolEntry::ends("python", &[3, 7], "2023-06-27"),
    EolEntry::ends("python", &[3, 8], "2024-10-07"),
    EolEntry::ends("python", &[3, 9], "2025-10-31"),
    EolEntry::ends("python", &[3, 10], "2026-10-01"),
    EolEntry::ends("python", &[3, 11], "2027-10-31"),
    EolEntry::ends("python", &[3, 12], "2028-10-31"),
    EolEntry::ends("python", &[3, 13], "2029-10-31"),
    EolEntry::ends("python", &[3, 14], "2030-10-31"),
    EolEntry::ends("python", &[3, 15], "2031-10-31"),
    // https://go.dev/doc/devel/release (the second newer release ends support)
    EolEntry::ends("go", &[1, 19], "2023-08-08"),
    EolEntry::ends("go", &[1, 20], "2024-02-06"),
    EolEntry::ends("go", &[1, 21], "2024-08-13"),
    EolEntry::ends("go", &[1, 22], "2025-02-11"),
    EolEntry::ends("go", &[1, 23], "2025-08-12"),
    EolEntry::ends("go", &[1, 24], "2026-02-10"),
    EolEntry::ends("go", &[1, 25], "2026-08-19"),
    // https://www.ruby-lang.org/en/downloads/branches/
    EolEntry::ends("ruby", &[2, 0], "2016-02-24"),
    EolEntry::ends("ruby", &[2, 1], "2017-03-31"),
    EolEntry::ends("ruby", &[2, 2], "2018-03-31"),
    EolEntry::ends("ruby", &[2, 3], "2019-03-31"),
    EolEntry::ends("ruby", &[2, 4], "2020-03-31"),
    EolEntry::ends("ruby", &[2, 5], "2021-04-05"),
    EolEntry::ends("ruby", &[2, 6], "2022-04-12"),
    EolEntry::ends("ruby", &[2, 7], "2023-03-31"),
    EolEntry::ends("ruby", &[3, 0], "2024-04-23"),
    EolEntry::ends("ruby", &[3, 1], "2025-03-26"),
    EolEntry::ends("ruby", &[3, 2], "2026-04-01"),
    EolEntry::ends("ruby", &[3, 3], "2027-03-31"),
    // https://adoptium.net/support/ (availability months use month-end)
    EolEntry::minimum("java", &[8], "2030-12"),
    EolEntry::minimum("java", &[11], "2027-10"),
    EolEntry::ends("java", &[16], "2021-09-30"),
    EolEntry::minimum("java", &[17], "2027-10"),
    EolEntry::ends("java", &[18], "2022-09-30"),
    EolEntry::ends("java", &[19], "2023-03-31"),
    EolEntry::ends("java", &[20], "2023-09-30"),
    EolEntry::minimum("java", &[21], "2029-12"),
    EolEntry::ends("java", &[22], "2024-09-30"),
    EolEntry::ends("java", &[23], "2025-03-31"),
    EolEntry::ends("java", &[24], "2025-09-30"),
    EolEntry::minimum("java", &[25], "2031-09"),
    EolEntry::ends("java", &[26], "2026-09-30"),
    EolEntry::ends("java", &[27], "2027-03-31"),
    // https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core
    EolEntry::ends("dotnet", &[1, 0], "2019-06-27"),
    EolEntry::ends("dotnet", &[1, 1], "2019-06-27"),
    EolEntry::ends("dotnet", &[2, 0], "2018-10-01"),
    EolEntry::ends("dotnet", &[2, 1], "2021-08-21"),
    EolEntry::ends("dotnet", &[2, 2], "2019-12-23"),
    EolEntry::ends("dotnet", &[3, 0], "2020-03-03"),
    EolEntry::ends("dotnet", &[3, 1], "2022-12-13"),
    EolEntry::ends("dotnet", &[5], "2022-05-10"),
    EolEntry::ends("dotnet", &[6], "2024-11-12"),
    EolEntry::ends("dotnet", &[7], "2024-05-14"),
    EolEntry::ends("dotnet", &[8], "2026-11-10"),
    EolEntry::ends("dotnet", &[9], "2026-11-10"),
    EolEntry::ends("dotnet", &[10], "2028-11-14"),
    EolEntry::ends("dotnet", &[11], "2028-11-14"),
    // https://www.php.net/supported-versions.php and https://www.php.net/eol.php
    EolEntry::ends("php", &[5, 3], "2014-08-14"),
    EolEntry::ends("php", &[5, 4], "2015-09-03"),
    EolEntry::ends("php", &[5, 5], "2016-07-21"),
    EolEntry::ends("php", &[5, 6], "2018-12-31"),
    EolEntry::ends("php", &[7, 0], "2019-01-10"),
    EolEntry::ends("php", &[7, 1], "2019-12-01"),
    EolEntry::ends("php", &[7, 2], "2020-11-30"),
    EolEntry::ends("php", &[7, 3], "2021-12-06"),
    EolEntry::ends("php", &[7, 4], "2022-11-28"),
    EolEntry::ends("php", &[8, 0], "2023-11-26"),
    EolEntry::ends("php", &[8, 1], "2025-12-31"),
    EolEntry::ends("php", &[8, 2], "2026-12-31"),
    EolEntry::ends("php", &[8, 3], "2027-12-31"),
    EolEntry::ends("php", &[8, 4], "2028-12-31"),
    EolEntry::ends("php", &[8, 5], "2029-12-31"),
    EolEntry::ends("php", &[8, 6], "2030-12-31"),
];

/// Compare dates in UTC as the schedules publish calendar days.
pub(crate) struct SupportWindow {
    today: Date,
    warning_cutoff: Date,
}

impl SupportWindow {
    pub(crate) fn new(now: Timestamp) -> Result<Self> {
        let today = now.to_zoned(TimeZone::UTC).date();
        Ok(Self {
            today,
            warning_cutoff: today
                .checked_add(Span::new().months(6))
                .context("Failed to compute EOL warning window")?,
        })
    }

    pub(crate) fn assess(&self, runtime: &str, version: &str) -> Result<SupportStatus> {
        let (numeric, suffix) = version_prefix_and_suffix(version);
        if is_preview_suffix(suffix) {
            return Ok(SupportStatus::Unknown);
        }
        let components = version_components(numeric);
        let Some(entry) = find_eol_entry(runtime, &components) else {
            return Ok(SupportStatus::Unknown);
        };
        match entry.support {
            SupportDate::End(date) => {
                let end = parse_eol_date(date)?;
                if self.today >= end {
                    Ok(SupportStatus::Ended(date))
                } else if self.warning_cutoff >= end {
                    Ok(SupportStatus::EndingSoon(date))
                } else {
                    Ok(SupportStatus::Active(date))
                }
            }
            SupportDate::Minimum(month) => {
                let minimum = parse_eol_date(&format!("{month}-01"))?;
                if self.today < minimum {
                    Ok(SupportStatus::MinimumSupport(month))
                } else {
                    Ok(SupportStatus::Unknown)
                }
            }
        }
    }
}

fn version_prefix_and_suffix(version: &str) -> (&str, &str) {
    let version = version.strip_prefix(['v', 'V']).unwrap_or(version);
    let end = version
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(version.len());
    version.split_at(end)
}

fn is_preview_suffix(suffix: &str) -> bool {
    let suffix = suffix.trim_start_matches(['-', '.', '_']);
    let kind = suffix
        .split(|c: char| !c.is_ascii_alphabetic())
        .next()
        .unwrap_or("");
    [
        "a", "alpha", "b", "beta", "rc", "pre", "preview", "dev", "ea", "nightly", "snapshot",
    ]
    .iter()
    .any(|candidate| kind.eq_ignore_ascii_case(candidate))
}

fn version_components(version: &str) -> Vec<u64> {
    version_prefix_and_suffix(version)
        .0
        .split('.')
        .map(str::parse)
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_default()
}

fn find_eol_entry(runtime: &str, components: &[u64]) -> Option<&'static EolEntry> {
    EOL_TABLE
        .iter()
        .find(|entry| entry.runtime == runtime && components.starts_with(entry.version_prefix))
}

fn parse_eol_date(value: &str) -> Result<Date> {
    Date::strptime("%Y-%m-%d", value).with_context(|| format!("Invalid EOL date {value:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(today: &str) -> SupportWindow {
        SupportWindow::new(today.parse().expect("fixed timestamp")).expect("valid window")
    }

    #[test]
    fn python_3_13_does_not_match_3_1() {
        let entry = find_eol_entry("python", &[3, 13]).unwrap();
        assert_eq!(entry.version_prefix, &[3, 13]);
    }

    #[test]
    fn node_major_only_matches_full_prefix() {
        assert!(find_eol_entry("node", &[16]).is_some());
        assert!(find_eol_entry("node", &[160]).is_none());
    }

    #[test]
    fn unknown_runtime_has_no_eol_entry() {
        assert!(find_eol_entry("rust", &[1, 75]).is_none());
    }

    #[test]
    fn lifecycle_table_contains_recent_eol_cycles() {
        let expected = [
            ("node", &[23][..], "2025-06-01"),
            ("node", &[25][..], "2026-06-01"),
            ("python", &[3, 14][..], "2030-10-31"),
            ("go", &[1, 23][..], "2025-08-12"),
            ("go", &[1, 24][..], "2026-02-10"),
            ("go", &[1, 25][..], "2026-08-19"),
            ("ruby", &[3, 2][..], "2026-04-01"),
            ("java", &[24][..], "2025-09-30"),
            ("dotnet", &[8][..], "2026-11-10"),
            ("php", &[8, 2][..], "2026-12-31"),
        ];
        for (runtime, version, date) in expected {
            assert_eq!(
                find_eol_entry(runtime, version).map(|entry| entry.support),
                Some(SupportDate::End(date)),
                "missing or stale lifecycle row for {runtime} {version:?}"
            );
        }
        assert!(find_eol_entry("ruby", &[3, 4]).is_none());
    }

    #[test]
    fn warning_cutoff_uses_calendar_months_in_utc() {
        let current = window("2026-01-31T12:00:00Z");
        assert_eq!(current.warning_cutoff, date(2026, 7, 31));
        let aug = window("2026-08-31T12:00:00Z");
        assert_eq!(aug.warning_cutoff, date(2027, 2, 28));
    }

    fn date(year: i16, month: i8, day: i8) -> Date {
        Date::new(year, month, day).expect("fixed calendar date")
    }

    #[test]
    fn version_components_parse_numeric_prefixes_only() {
        assert_eq!(version_components("3.13.1-1"), vec![3, 13, 1]);
        assert_eq!(version_components("1.20"), vec![1, 20]);
        assert_eq!(version_components("20.10.0"), vec![20, 10, 0]);
        assert_eq!(version_components("v22"), vec![22]);
        assert!(version_components("lts/hydrogen").is_empty());
        assert!(version_components("16..2").is_empty());
        assert!(version_components("16.123456789012345678901").is_empty());
    }

    #[test]
    fn eol_prefix_match_never_confuses_component_boundaries() {
        let installed = version_components("3.13.2");
        assert!(installed.starts_with(&[3, 13]));
        assert!(!installed.starts_with(&[3, 1]));
        let go = version_components("1.30.1");
        assert!(go.starts_with(&[1, 30]));
        assert!(!go.starts_with(&[1, 3]));
    }

    #[test]
    fn parse_eol_date_accepts_iso_dates() {
        assert_eq!(parse_eol_date("2025-04-30").unwrap(), date(2025, 4, 30));
    }

    #[test]
    fn parse_eol_date_rejects_garbage() {
        let error = parse_eol_date("not-a-date").unwrap_err();
        assert!(error.to_string().contains("Invalid EOL date"), "{error}");
    }

    #[test]
    fn schedule_dates_are_valid_and_version_prefixes_are_unique() {
        for (index, entry) in EOL_TABLE.iter().enumerate() {
            assert!(super::super::NATIVE_RUNTIMES.contains(&entry.runtime));
            let date = match entry.support {
                SupportDate::End(date) => date.to_owned(),
                SupportDate::Minimum(month) => format!("{month}-01"),
            };
            assert!(parse_eol_date(&date).is_ok(), "{date}");
            for previous in &EOL_TABLE[..index] {
                assert!(
                    previous.runtime != entry.runtime
                        || (!entry.version_prefix.starts_with(previous.version_prefix)
                            && !previous.version_prefix.starts_with(entry.version_prefix))
                );
            }
        }
    }

    #[test]
    fn assessment_distinguishes_schedule_boundaries_and_previews() -> Result<()> {
        use SupportStatus::*;
        for (time, runtime, version, expected) in [
            (
                "2026-10-29T00:00:00Z",
                "node",
                "22.22.0",
                Active("2027-04-30"),
            ),
            (
                "2026-10-30T00:00:00Z",
                "node",
                "22.22.0",
                EndingSoon("2027-04-30"),
            ),
            (
                "2027-04-30T00:00:00Z",
                "node",
                "22.22.0",
                Ended("2027-04-30"),
            ),
            (
                "2026-11-26T00:00:00Z",
                "java",
                "11.0.33+1",
                MinimumSupport("2027-10"),
            ),
            ("2027-10-01T00:00:00Z", "java", "11.0.33+1", Unknown),
            (
                "2026-11-26T00:00:00Z",
                "java",
                "8u511-b01",
                MinimumSupport("2030-12"),
            ),
            (
                "2026-11-26T00:00:00Z",
                "dotnet",
                "11.0.100-rc.3.24001",
                Unknown,
            ),
            ("2026-11-26T00:00:00Z", "python", "3.15.0rc2", Unknown),
            (
                "2026-11-26T00:00:00Z",
                "python",
                "3.15.1-1",
                Active("2031-10-31"),
            ),
        ] {
            assert_eq!(
                window(time).assess(runtime, version)?,
                expected,
                "{runtime} {version} at {time}"
            );
        }
        Ok(())
    }
}
