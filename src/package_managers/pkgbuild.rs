//! PKGBUILD metadata parser
//!
//! Extracts package information from PKGBUILD files without a Bash interpreter.
//! Handles multi-line arrays properly for accurate dependency extraction.

use alpm_types::Version;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

const MAX_PKGBUILD_BYTES: u64 = 1024 * 1024;

/// Upper bound for one expanded PKGBUILD variable value.
///
/// A PKGBUILD is untrusted input, and variable substitution is recursive: a
/// chain of assignments that reference each other doubles the expanded value
/// at every level. Without a budget a ~2 KB file expands to gigabytes before
/// the review prompt is even shown.
const MAX_SUBSTITUTED_VALUE_BYTES: usize = 1024 * 1024;

fn invalid_pkgbuild_data(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into())
}

/// Read a bounded regular file safely, preventing symlink and special-file
/// attacks on Unix.
fn safe_read_file(path: &Path) -> std::io::Result<String> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    let mut file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(invalid_pkgbuild_data("PKGBUILD must be a regular file"));
    }
    if metadata.len() > MAX_PKGBUILD_BYTES {
        return Err(invalid_pkgbuild_data(format!(
            "PKGBUILD exceeds the {MAX_PKGBUILD_BYTES}-byte limit"
        )));
    }

    let mut bytes = Vec::with_capacity(metadata.len().try_into().unwrap_or(0));
    file.by_ref()
        .take(MAX_PKGBUILD_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_PKGBUILD_BYTES {
        return Err(invalid_pkgbuild_data(format!(
            "PKGBUILD exceeds the {MAX_PKGBUILD_BYTES}-byte limit"
        )));
    }
    String::from_utf8(bytes).map_err(|error| invalid_pkgbuild_data(error.to_string()))
}

#[derive(Debug, Clone)]
pub struct PkgBuild {
    pub name: String,
    pub version: Version,
    pub release: String,
    pub description: String,
    pub url: String,
    pub license: Vec<String>,
    pub depends: Vec<String>,
    pub makedepends: Vec<String>,
    pub checkdepends: Vec<String>,
    pub sources: Vec<String>,
    pub sha256sums: Vec<String>,
    pub validpgpkeys: Vec<String>,
}

impl Default for PkgBuild {
    fn default() -> Self {
        Self {
            name: String::new(),
            version: super::types::zero_version(),
            release: String::new(),
            description: String::new(),
            url: String::new(),
            license: Vec::new(),
            depends: Vec::new(),
            makedepends: Vec::new(),
            checkdepends: Vec::new(),
            sources: Vec::new(),
            sha256sums: Vec::new(),
            validpgpkeys: Vec::new(),
        }
    }
}

fn strip_inline_comment(line: &str) -> &str {
    let mut quote = None;
    let mut escaped = false;

    for (index, character) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' && quote != Some('\'') {
            escaped = true;
            continue;
        }

        match quote {
            Some(delimiter) if character == delimiter => quote = None,
            None if character == '\'' || character == '"' => quote = Some(character),
            None if character == '#'
                && (index == 0
                    || line[..index]
                        .chars()
                        .next_back()
                        .is_some_and(char::is_whitespace)) =>
            {
                return &line[..index];
            }
            Some(_) | None => {}
        }
    }

    line
}

fn is_shell_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|character| character == '_' || character.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn function_declaration(line: &str) -> bool {
    let line = strip_inline_comment(line).trim();
    if let Some(rest) = line.strip_prefix("function ") {
        let name = rest
            .split(|character: char| {
                character.is_whitespace() || character == '(' || character == '{'
            })
            .next()
            .unwrap_or_default();
        return is_shell_identifier(name);
    }

    let Some((name, rest)) = line.split_once('(') else {
        return false;
    };
    is_shell_identifier(name.trim()) && rest.trim_start().starts_with(')')
}

fn unquoted_braces(line: &str) -> (u32, u32) {
    let mut quote = None;
    let mut escaped = false;
    let mut opens = 0;
    let mut closes = 0;

    for character in strip_inline_comment(line).chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' && quote != Some('\'') {
            escaped = true;
            continue;
        }
        match quote {
            Some(delimiter) if character == delimiter => quote = None,
            None if character == '\'' || character == '"' => quote = Some(character),
            None if character == '{' => opens += 1,
            None if character == '}' => closes += 1,
            Some(_) | None => {}
        }
    }
    (opens, closes)
}

#[derive(Default)]
struct ArrayCompletion {
    quote: Option<char>,
    escaped: bool,
    depth: u32,
}

impl ArrayCompletion {
    fn scan(&mut self, value: &str) -> Result<bool> {
        for character in value.chars() {
            #[cfg(test)]
            tests::ARRAY_SCAN_BYTES.with(|count| count.set(count.get() + character.len_utf8()));
            if self.escaped {
                self.escaped = false;
                continue;
            }
            if character == '\\' && self.quote != Some('\'') {
                self.escaped = true;
                continue;
            }
            match self.quote {
                Some(delimiter) if character == delimiter => self.quote = None,
                None if character == '\'' || character == '"' => self.quote = Some(character),
                None if character == '(' => self.depth = self.depth.saturating_add(1),
                None if character == ')' => {
                    anyhow::ensure!(self.depth > 0, "unexpected closing parenthesis in array");
                    self.depth -= 1;
                    if self.depth == 0 {
                        return Ok(true);
                    }
                }
                Some(_) | None => {}
            }
        }
        Ok(false)
    }
}

#[derive(Default)]
struct SubstitutionNode {
    children: HashMap<u8, usize>,
    index: Option<usize>,
}

/// Find only replacement passes that can change the value. This is an index
/// over the existing ordered passes, not shell token expansion: bare names
/// still match prefixes and inserted references only run in later passes.
struct SubstitutionIndex {
    nodes: Vec<SubstitutionNode>,
}

impl SubstitutionIndex {
    fn new(substitutions: &[(&String, &String)]) -> Self {
        let mut nodes = vec![SubstitutionNode::default()];
        for (index, (key, _)) in substitutions.iter().enumerate() {
            let mut node = 0;
            for byte in key.bytes() {
                #[cfg(test)]
                tests::SUBSTITUTION_SCAN_BYTES.with(|count| count.set(count.get() + 1));
                node = if let Some(&child) = nodes[node].children.get(&byte) {
                    child
                } else {
                    let child = nodes.len();
                    nodes.push(SubstitutionNode::default());
                    nodes[node].children.insert(byte, child);
                    child
                };
            }
            nodes[node].index = Some(index);
        }
        Self { nodes }
    }

    fn next(&self, value: &str, minimum: usize) -> Option<usize> {
        #[cfg(test)]
        tests::SUBSTITUTION_SCAN_BYTES.with(|count| count.set(count.get() + value.len()));
        let mut next = None;
        for (offset, _) in value.match_indices('$') {
            // The parser historically admits an empty assignment name; its
            // bare pattern is "$", including the start of braced references.
            if let Some(index) = self.nodes[0].index
                && index >= minimum
            {
                next = Some(next.map_or(index, |previous: usize| previous.min(index)));
            }
            let mut tail = &value.as_bytes()[offset + 1..];
            let braced = tail.first() == Some(&b'{');
            if braced {
                tail = &tail[1..];
            }
            let mut node = 0;
            loop {
                if let Some(index) = self.nodes[node].index
                    && index >= minimum
                    && (!braced || tail.first() == Some(&b'}'))
                {
                    next = Some(next.map_or(index, |previous: usize| previous.min(index)));
                }
                let Some(byte) = tail.first() else { break };
                #[cfg(test)]
                tests::SUBSTITUTION_SCAN_BYTES.with(|count| count.set(count.get() + 1));
                let Some(&child) = self.nodes[node].children.get(byte) else {
                    break;
                };
                node = child;
                tail = &tail[1..];
            }
        }
        next
    }
}

impl PkgBuild {
    /// Parse a PKGBUILD file
    ///
    /// # Security
    /// Uses `O_NOFOLLOW` on Unix to prevent symlink attacks where a malicious
    /// PKGBUILD symlink could point to sensitive files like /etc/passwd.
    pub fn parse(path: &Path) -> Result<Self> {
        let content = safe_read_file(path)
            .with_context(|| format!("Failed to read PKGBUILD at {}", path.display()))?;

        Self::parse_content(&content)
    }

    /// Parse PKGBUILD content - handles multi-line arrays
    pub fn parse_content(content: &str) -> Result<Self> {
        let mut vars: HashMap<String, String> = HashMap::new();

        // First pass: extract top-level variables including multi-line arrays.
        // Assignments inside prepare/build/package functions are shell-local
        // implementation details and must not override package metadata.
        let mut lines = content.lines();
        let mut function_depth = 0_u32;
        let mut awaiting_function_body = false;
        while let Some(line) = lines.next() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if function_depth > 0 {
                let (opens, closes) = unquoted_braces(line);
                function_depth = function_depth
                    .checked_add(opens)
                    .context("function brace depth overflow")?;
                anyhow::ensure!(
                    closes <= function_depth,
                    "unexpected closing brace in PKGBUILD function"
                );
                function_depth -= closes;
                continue;
            }

            if awaiting_function_body {
                let (opens, closes) = unquoted_braces(line);
                anyhow::ensure!(
                    opens > 0,
                    "PKGBUILD function body is missing an opening brace"
                );
                anyhow::ensure!(
                    closes <= opens,
                    "unexpected closing brace in PKGBUILD function"
                );
                function_depth = opens - closes;
                awaiting_function_body = false;
                continue;
            }

            if function_declaration(line) {
                let (opens, closes) = unquoted_braces(line);
                anyhow::ensure!(
                    closes <= opens,
                    "unexpected closing brace in PKGBUILD function"
                );
                if opens == 0 {
                    awaiting_function_body = true;
                } else {
                    function_depth = opens - closes;
                }
                continue;
            }

            let Some((key, val)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim();
            let val = strip_inline_comment(val).trim();
            if !key
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            {
                continue;
            }

            if val.starts_with('(') {
                let mut array_content = val.to_string();
                let mut completion = ArrayCompletion::default();
                let mut complete = completion.scan(val)?;
                while !complete {
                    let Some(next_line) = lines.next() else {
                        anyhow::bail!("unterminated array assignment for {key}");
                    };
                    let start = array_content.len();
                    array_content.push(' ');
                    array_content.push_str(strip_inline_comment(next_line));
                    complete = completion.scan(&array_content[start..])?;
                }
                vars.insert(key.to_string(), array_content);
            } else {
                vars.insert(
                    key.to_string(),
                    val.trim_matches('"').trim_matches('\'').to_string(),
                );
            }
        }

        anyhow::ensure!(
            function_depth == 0 && !awaiting_function_body,
            "unterminated function body in PKGBUILD"
        );

        // Sort substitution sources once, longest first, so shorter variable
        // names cannot partially replace longer names.
        let mut substitutions: Vec<_> = vars.iter().collect();
        substitutions.sort_by_key(|(key, _)| std::cmp::Reverse(key.len()));
        let substitution_index = SubstitutionIndex::new(&substitutions);
        let substitute = |val: &str| -> Result<String> {
            let mut result = val.to_string();
            let mut minimum = 0;
            while minimum < substitutions.len() {
                // Preserve the original guard's first failing pass even for
                // oversized parse_content callers whose next match is later.
                let index = if result.len() > MAX_SUBSTITUTED_VALUE_BYTES {
                    minimum
                } else if let Some(index) = substitution_index.next(&result, minimum) {
                    index
                } else {
                    break;
                };
                let (key, value) = substitutions[index];
                #[cfg(test)]
                tests::SUBSTITUTION_SCAN_BYTES.with(|count| count.set(count.get() + result.len()));
                result = result.replace(&format!("${key}"), value);
                #[cfg(test)]
                tests::SUBSTITUTION_SCAN_BYTES.with(|count| count.set(count.get() + result.len()));
                result = result.replace(&format!("${{{key}}}"), value);
                anyhow::ensure!(
                    result.len() <= MAX_SUBSTITUTED_VALUE_BYTES,
                    "PKGBUILD variable '{key}' expands beyond {MAX_SUBSTITUTED_VALUE_BYTES} bytes"
                );
                minimum = index + 1;
            }
            Ok(result)
        };
        let scalar = |key: &str| -> Result<String> {
            vars.get(key)
                .map_or_else(|| Ok(String::new()), |value| substitute(value))
        };
        let array = |key: &str| -> Result<Vec<String>> {
            vars.get(key)
                .map_or_else(|| Ok(Vec::new()), |value| parse_array(&substitute(value)?))
        };

        Ok(Self {
            name: scalar("pkgname")?,
            // A PKGBUILD is an untrusted boundary: a present pkgver that fails
            // the strict parser must fail the parse with a typed error instead
            // of comparing as a fabricated 0 (ARCH-R14). A missing pkgver keeps
            // the pre-existing explicit zero fallback.
            version: match vars.get("pkgver") {
                None => super::types::zero_version(),
                Some(v) => {
                    let raw = substitute(v)?;
                    super::types::parse_version(&raw)
                        .with_context(|| format!("PKGBUILD has an unparseable pkgver: '{raw}'"))?
                }
            },
            release: scalar("pkgrel")?,
            description: scalar("pkgdesc")?,
            url: scalar("url")?,
            license: array("license")?,
            depends: array("depends")?,
            makedepends: array("makedepends")?,
            checkdepends: array("checkdepends")?,
            sources: array("source")?,
            sha256sums: array("sha256sums")?,
            validpgpkeys: array("validpgpkeys")?,
        })
    }
}

fn parse_array(value: &str) -> Result<Vec<String>> {
    let cleaned = value
        .lines()
        .map(strip_inline_comment)
        .collect::<Vec<_>>()
        .join(" ");
    let trimmed = cleaned.trim();
    let inner = trimmed
        .strip_prefix('(')
        .and_then(|value| value.strip_suffix(')'))
        .context("array value must be enclosed in parentheses")?;

    let mut items = Vec::new();
    let mut token = String::new();
    let mut token_started = false;
    let mut quote = None;
    let mut escaped = false;

    for character in inner.chars() {
        if escaped {
            token.push(character);
            token_started = true;
            escaped = false;
            continue;
        }
        if character == '\\' && quote != Some('\'') {
            escaped = true;
            token_started = true;
            continue;
        }
        match quote {
            Some(delimiter) if character == delimiter => quote = None,
            Some(_) => token.push(character),
            None if character == '\'' || character == '"' => {
                quote = Some(character);
                token_started = true;
            }
            None if character.is_whitespace() => {
                if token_started {
                    items.push(std::mem::take(&mut token));
                    token_started = false;
                }
            }
            None => {
                token.push(character);
                token_started = true;
            }
        }
    }

    anyhow::ensure!(quote.is_none(), "unterminated quote in array");
    anyhow::ensure!(!escaped, "unterminated escape in array");
    if token_started {
        items.push(token);
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    thread_local! {
        pub(super) static SUBSTITUTION_SCAN_BYTES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
        pub(super) static ARRAY_SCAN_BYTES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    #[test]
    fn unrelated_assignments_do_not_multiply_metadata_scan_work() {
        use std::fmt::Write as _;

        for assignments in [0, 3200, 32000] {
            for reference in ["", "$zzzzzzzzzz", "${unknown}"] {
                let mut content = String::from("pkgname=demo\npkgver=1\npkgrel=1\nzzzzzzzzzz=ok\n");
                for index in 0..assignments {
                    writeln!(content, "a{index:07}=x").expect("fixture");
                }
                let description = "z".repeat(524_288);
                writeln!(content, "pkgdesc='{description}{reference}'").expect("fixture");
                assert!(content.len() < MAX_PKGBUILD_BYTES as usize);
                SUBSTITUTION_SCAN_BYTES.with(|count| count.set(0));
                let directory = tempfile::tempdir().expect("tempdir");
                let path = directory.path().join("PKGBUILD");
                std::fs::write(&path, &content).expect("fixture");
                let package = PkgBuild::parse(&path).expect("admitted metadata");
                assert_eq!(
                    package.description,
                    format!(
                        "{description}{}",
                        if reference == "$zzzzzzzzzz" {
                            "ok"
                        } else {
                            reference
                        }
                    )
                );
                let work = SUBSTITUTION_SCAN_BYTES.with(std::cell::Cell::get);
                assert!(
                    work <= 8 * content.len(),
                    "scanned {work} bytes for {} input bytes",
                    content.len()
                );
                println!(
                    "substitution assignments={assignments} reference={reference:?} input_bytes={} work_bytes={work}",
                    content.len()
                );
            }
        }
    }

    #[test]
    fn array_continuations_scan_each_appended_byte_once() {
        for lines in [2000, 8000, 100_000] {
            let content = format!(
                "pkgname=demo\npkgver=1\npkgrel=1\ndepends=(\n{}",
                " ( \n".repeat(lines)
            );
            ARRAY_SCAN_BYTES.with(|count| count.set(0));
            let directory = tempfile::tempdir().expect("tempdir");
            let path = directory.path().join("PKGBUILD");
            std::fs::write(&path, &content).expect("fixture");
            let error = PkgBuild::parse(&path).expect_err("unterminated array");
            assert!(
                error
                    .to_string()
                    .contains("unterminated array assignment for depends")
            );
            let work = ARRAY_SCAN_BYTES.with(std::cell::Cell::get);
            assert!(
                work <= content.len(),
                "scanned {work} bytes for {} input bytes",
                content.len()
            );
            println!(
                "array lines={lines} input_bytes={} work_bytes={work}",
                content.len()
            );
        }
    }

    #[test]
    fn substitutions_preserve_prefixes_and_ordered_inserted_references() {
        let package = PkgBuild::parse_content(
            "longname='$a'\na=X\npkgdesc='$longname ${longname} $ax ${ax} $missing'\nsource=('$longname' '${a}')\n",
        ).expect("ordered references");
        assert_eq!(package.description, "X X Xx ${ax} $missing");
        assert_eq!(package.sources, ["X", "X"]);

        let package = PkgBuild::parse_content("longname=Y\na='$longname'\npkgdesc='$a ${a}'\n")
            .expect("references to already processed names stay literal");
        assert_eq!(package.description, "$longname $longname");

        let package = PkgBuild::parse_content("a='${a}'\npkgdesc='$a'\n")
            .expect("bare pass followed by braced pass");
        assert_eq!(package.description, "${a}");
    }

    #[test]
    fn empty_assignment_name_preserves_bare_dollar_replacement() {
        let package = PkgBuild::parse_content("=Q\npkgdesc='${x}'\n")
            .expect("historically admitted empty name");
        assert_eq!(package.description, "Q{x}");
    }

    #[test]
    fn array_continuations_preserve_quote_escape_and_nesting_state() {
        let package = PkgBuild::parse_content(
            "depends=(\n\"left (\nright )\"\n'quoted ( )'\n((nested))\nescaped\\\n\\)\n) # ignored closing comment\npkgdesc=after\n",
        ).expect("complete multi-line array");
        assert_eq!(
            package.depends,
            ["left ( right )", "quoted ( )", "((nested))", "escaped )"]
        );
        assert_eq!(package.description, "after");
    }

    #[test]
    fn oversized_pkgbuild_file_is_rejected_before_parsing() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("PKGBUILD");
        std::fs::write(&path, vec![b'x'; MAX_PKGBUILD_BYTES as usize + 1]).expect("write");

        let error = PkgBuild::parse(&path).expect_err("oversized PKGBUILD must fail");

        assert!(format!("{error:#}").contains("exceeds"));
    }

    #[cfg(unix)]
    #[test]
    fn pkgbuild_fifo_is_rejected_without_blocking_for_a_writer() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("PKGBUILD");
        nix::unistd::mkfifo(&path, nix::sys::stat::Mode::S_IRUSR).expect("mkfifo");

        let error = PkgBuild::parse(&path).expect_err("FIFO must not be read as PKGBUILD");

        assert!(format!("{error:#}").contains("regular file"));
    }

    #[test]
    fn arrays_preserve_quoted_items_with_spaces() {
        let package = PkgBuild::parse_content(
            r#"
                pkgname=demo
                pkgver=1
                pkgrel=1
                source=("named source::https://example.test/archive.tar.gz" 'local patch.diff')
            "#,
        )
        .expect("valid quoted array");

        assert_eq!(
            package.sources,
            [
                "named source::https://example.test/archive.tar.gz",
                "local patch.diff"
            ]
        );
    }

    #[test]
    fn function_assignments_do_not_override_top_level_metadata() {
        let package = PkgBuild::parse_content(
            r#"
                pkgname=demo
                pkgver=1
                pkgrel=1
                pkgdesc="top-level description"
                validpgpkeys=(TOPLEVELKEY)

                prepare() {
                    pkgdesc="prepare-local description"
                    validpgpkeys=(PREPAREKEY)
                }

                package_demo()
                {
                    pkgdesc="split package description"
                    validpgpkeys=(SPLITKEY)
                }
            "#,
        )
        .expect("valid PKGBUILD functions");

        assert_eq!(package.description, "top-level description");
        assert_eq!(package.validpgpkeys, ["TOPLEVELKEY"]);
    }

    #[test]
    fn exponential_variable_expansion_is_rejected() {
        use std::fmt::Write as _;

        // Every level doubles the previous value, so a ~1 KB PKGBUILD would
        // otherwise expand to gigabytes inside `substitute` before the review
        // prompt is even shown.
        let mut pkgbuild = String::new();
        let mut previous = String::new();
        for level in 1..=24 {
            let key = "a".repeat(level);
            let value = if level == 1 {
                "X".to_string()
            } else {
                format!("${previous}${previous}")
            };
            writeln!(pkgbuild, "{key}=\"{value}\"").expect("write fixture");
            previous = key;
        }
        writeln!(pkgbuild, "pkgname=\"${previous}${previous}\"").expect("write fixture");
        pkgbuild.push_str("pkgver=1\npkgrel=1\n");

        let error =
            PkgBuild::parse_content(&pkgbuild).expect_err("exponential expansion must be rejected");
        assert!(
            error.to_string().contains("expands beyond"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn ordinary_variable_references_still_expand() {
        let package = PkgBuild::parse_content(
            r#"
                _pkgname=demo
                pkgname="$_pkgname"
                pkgver=1.2.3
                pkgrel=1
                pkgdesc="${_pkgname} utility"
                url="https://example.com/$_pkgname"
                source=("$_pkgname-$pkgver.tar.gz")
            "#,
        )
        .expect("ordinary substitution must keep working");

        assert_eq!(package.name, "demo");
        assert_eq!(package.description, "demo utility");
        assert_eq!(package.url, "https://example.com/demo");
        assert_eq!(package.sources, ["demo-1.2.3.tar.gz"]);
    }

    #[test]
    fn unterminated_function_body_is_rejected() {
        let error = PkgBuild::parse_content(
            r"
                pkgname=demo
                pkgver=1
                build() {
                    local mode=release
            ",
        )
        .expect_err("unterminated function must not hide the remainder of the file");

        assert!(
            error.to_string().contains("unterminated function"),
            "{error}"
        );
    }

    #[test]
    fn unterminated_array_is_rejected() {
        let error = PkgBuild::parse_content(
            r#"
                pkgname=demo
                pkgver=1
                pkgrel=1
                depends=("openssl"
            "#,
        )
        .expect_err("unterminated arrays must not absorb the remainder of the file");

        assert!(error.to_string().contains("unterminated array"), "{error}");
    }

    #[test]
    fn inline_comments_do_not_absorb_following_assignments() {
        let package = PkgBuild::parse_content(
            r#"
                pkgname = "demo" # package name
                pkgver = "1.2.3" # release version
                pkgrel = "1" # package release
                depends = ("openssl" "zlib") # dependency list
                source = (https://example.test/archive#fragment) # source URL
            "#,
        )
        .expect("valid PKGBUILD metadata");

        assert_eq!(package.name, "demo");
        assert_eq!(package.version.to_string(), "1.2.3");
        assert_eq!(package.release, "1");
        assert_eq!(package.depends, ["openssl", "zlib"]);
        assert_eq!(package.sources, ["https://example.test/archive#fragment"]);
    }
}
