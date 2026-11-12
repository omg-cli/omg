//! Structured Rust syntax facts; these facts confer no correspondence or coverage credit.

use proc_macro2::{Span, TokenStream, TokenTree};
use serde::Serialize;
use std::{
    fmt,
    io::{self, Write},
};
use syn::{
    spanned::Spanned,
    visit::{self, Visit},
};

/// Resource ceilings may be tightened, but never raised beyond the prototype contract.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_input_bytes: usize,
    pub max_nodes: usize,
    pub max_depth: usize,
    pub max_output_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_input_bytes: 1_048_576,
            max_nodes: 50_000,
            max_depth: 128,
            max_output_bytes: 16_777_216,
        }
    }
}

/// A refusal carries no partial inventory or implied acceptance.
#[derive(Debug)]
pub struct Error(String);
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl std::error::Error for Error {}
fn refuse(message: impl Into<String>) -> Error {
    Error(message.into())
}

/// Half-open UTF-8 source byte offsets.
#[derive(Debug, Clone, Serialize)]
pub struct ByteRange {
    pub start: usize,
    pub end: usize,
}
/// One-based line and zero-based UTF-8 byte column.
#[derive(Debug, Clone, Serialize)]
pub struct Position {
    pub line: usize,
    pub byte_column: usize,
}
/// Half-open positions in the original source.
#[derive(Debug, Clone, Serialize)]
pub struct LineByteColumnRange {
    pub start: Position,
    pub end: Position,
}
/// Byte and line projections of the same original-source span.
#[derive(Debug, Clone, Serialize)]
pub struct SourceSpan {
    pub byte_range: ByteRange,
    pub line_byte_column_range: LineByteColumnRange,
}
/// A direct syntax child role, without any name or binding resolution.
#[derive(Debug, Serialize)]
pub struct Role {
    pub role: &'static str,
    pub span: SourceSpan,
}
/// A pre-order syntax node with its nearest recorded lexical parent.
#[derive(Debug, Serialize)]
pub struct Node {
    pub id: usize,
    pub parent: Option<usize>,
    pub kind: &'static str,
    pub span: SourceSpan,
    pub name: Option<String>,
    pub attributes: Vec<SourceSpan>,
    pub signature: Option<SourceSpan>,
    pub parameters: Vec<SourceSpan>,
    pub body: Option<SourceSpan>,
    pub roles: Vec<Role>,
    pub opaque: bool,
}
/// Exact-source syntax inventory. IDs are stable only for identical input and schema.
#[derive(Debug, Serialize)]
pub struct Inventory {
    pub schema: &'static str,
    pub acceptance: bool,
    pub source_bytes: usize,
    pub nodes: Vec<Node>,
}

/// Inventories Rust syntax using the fixed resource ceilings.
///
/// # Errors
/// Refuses malformed Rust, invalid spans, exhausted resources and unsupported lexical complexity.
pub fn inventory(source: &str) -> Result<Inventory, Error> {
    inventory_with_limits(source, Limits::default())
}

/// Inventories syntax with caller-tightened resource ceilings and no partial success.
///
/// # Errors
/// Refuses raised ceilings, malformed Rust, exhausted resources and invalid spans.
pub fn inventory_with_limits(source: &str, limits: Limits) -> Result<Inventory, Error> {
    let ceiling = Limits::default();
    if limits.max_input_bytes > ceiling.max_input_bytes
        || limits.max_nodes > ceiling.max_nodes
        || limits.max_depth > ceiling.max_depth
        || limits.max_output_bytes > ceiling.max_output_bytes
    {
        return Err(refuse("limits exceed fixed ceilings"));
    }
    if source.len() > limits.max_input_bytes {
        return Err(refuse("input byte limit exceeded"));
    }
    let mut token_source = source.to_owned();
    let prefix = if source.starts_with('\u{feff}') {
        token_source.replace_range(..3, "   ");
        3
    } else {
        0
    };
    if source[prefix..].starts_with("#!") && !source[prefix..].starts_with("#![") {
        let end = source.find('\n').unwrap_or(source.len());
        token_source.replace_range(prefix..end, &" ".repeat(end - prefix));
    }
    lexical_guard(&token_source, limits.max_depth)?;
    std::thread::scope(|scope| {
        let worker = std::thread::Builder::new()
            .name("rust-syntax-inventory".into())
            .stack_size(16 * 1024 * 1024)
            .spawn_scoped(scope, || inventory_parsed(source, &token_source, limits))
            .map_err(|e| refuse(format!("parser thread unavailable: {e}")))?;
        match worker.join() {
            Ok(result) => result,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    })
}

fn inventory_parsed(source: &str, token_source: &str, limits: Limits) -> Result<Inventory, Error> {
    let tokens: TokenStream = token_source
        .parse()
        .map_err(|e| refuse(format!("token parse failure: {e}")))?;
    // Token complexity bounds delimiter-free recursion independently of lexical depth.
    token_guard(tokens, 512, limits.max_depth)?;
    let file =
        syn::parse_file(token_source).map_err(|e| refuse(format!("Rust parse failure: {e}")))?;
    let mut visitor = InventoryVisitor {
        source,
        lines: vec![0],
        limits,
        nodes: Vec::new(),
        parents: Vec::new(),
        error: None,
    };
    visitor.lines.extend(
        source
            .bytes()
            .enumerate()
            .filter_map(|(i, b)| (b == b'\n').then_some(i + 1)),
    );
    visitor.enter_range("file", 0..source.len());
    visitor.visit_file(&file);
    visitor.leave();
    if let Some(error) = visitor.error {
        return Err(error);
    }
    let result = Inventory {
        schema: "rust-syntax-inventory-v1",
        acceptance: false,
        source_bytes: source.len(),
        nodes: visitor.nodes,
    };
    let mut sink = BoundedWriter {
        remaining: limits.max_output_bytes,
    };
    serde_json::to_writer(&mut sink, &result)
        .map_err(|e| refuse(format!("output limit or serialization failure: {e}")))?;
    Ok(result)
}

struct BoundedWriter {
    remaining: usize,
}
impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.remaining = self
            .remaining
            .checked_sub(bytes.len())
            .ok_or_else(|| io::Error::other("output byte limit exceeded"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// Reject delimiter nesting before proc-macro2 constructs its recursive token groups.
fn lexical_guard(source: &str, max_depth: usize) -> Result<(), Error> {
    let b = source.as_bytes();
    let mut i = 0;
    let mut depth = 0usize;
    while i < b.len() {
        if b[i..].starts_with(b"//") {
            i += 2;
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if b[i..].starts_with(b"/*") {
            i += 2;
            let mut comments = 1usize;
            while i < b.len() && comments > 0 {
                if b[i..].starts_with(b"/*") {
                    comments += 1;
                    i += 2;
                    if comments > max_depth {
                        return Err(refuse("comment depth limit exceeded"));
                    }
                } else if b[i..].starts_with(b"*/") {
                    comments -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            continue;
        }
        if b[i] == b'r' {
            let mut end = i + 1;
            while end < b.len() && b[end] == b'#' {
                end += 1;
            }
            if end < b.len() && b[end] == b'"' {
                let hashes = end - i - 1;
                i = end + 1;
                while i < b.len() {
                    if b[i] == b'"'
                        && b.get(i + 1..i + 1 + hashes)
                            .is_some_and(|tail| tail.iter().all(|v| *v == b'#'))
                    {
                        i += 1 + hashes;
                        break;
                    }
                    i += 1;
                }
                continue;
            }
        }
        if b[i] == b'"' {
            i += 1;
            while i < b.len() {
                if b[i] == b'\\' {
                    i = (i + 2).min(b.len());
                } else if b[i] == b'"' {
                    i += 1;
                    break;
                } else {
                    i += 1;
                }
            }
            continue;
        }
        if b[i] == b'\'' {
            let mut end = i + 1;
            if b.get(end) == Some(&b'\\') {
                end += 1;
                if b.get(end) == Some(&b'u') && b.get(end + 1) == Some(&b'{') {
                    end += 2;
                    while end < b.len() && b[end] != b'}' {
                        end += 1;
                    }
                    end += 1;
                } else if b.get(end) == Some(&b'x') {
                    end += 3;
                } else {
                    end += 1;
                }
            } else if let Some(ch) = source.get(end..).and_then(|s| s.chars().next()) {
                end += ch.len_utf8();
            }
            if b.get(end) == Some(&b'\'') {
                i = end + 1;
                continue;
            }
        }
        match b[i] {
            b'(' | b'[' | b'{' => {
                depth += 1;
                if depth > max_depth {
                    return Err(refuse("lexical depth limit exceeded"));
                }
            }
            b')' | b']' | b'}' => {
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
        i += 1;
    }
    Ok(())
}

// Conservative pre-parse recursion guard, including delimiter-free unary/type chains.
fn token_guard(
    tokens: TokenStream,
    max_depth: usize,
    structural_limit: usize,
) -> Result<(), Error> {
    let mut pending = vec![(tokens, 0usize, true, 0usize)];
    while let Some((stream, base, container, structural_base)) = pending.pop() {
        let mut angles = 0usize;
        let mut arrow_prefix = false;
        let mut cost = base;
        let mut item_body = false;
        let mut item_container = false;
        for token in stream {
            cost = cost
                .checked_add(1)
                .ok_or_else(|| refuse("token complexity overflow"))?;
            if cost > max_depth {
                return Err(refuse(format!(
                    "token complexity limit exceeded at byte {}",
                    token.span().byte_range().start
                )));
            }
            let is_arrow_end = arrow_prefix;
            arrow_prefix = matches!(&token, TokenTree::Punct(p) if matches!(p.as_char(), '-' | '=') && p.spacing() == proc_macro2::Spacing::Joint);
            match token {
                TokenTree::Punct(ref p) if p.as_char() == '<' => {
                    // Conservatively count angle groups without resolving generic syntax.
                    angles += 1;
                    if structural_base + angles > structural_limit {
                        return Err(refuse("preparse structural depth limit exceeded"));
                    }
                }
                TokenTree::Punct(ref p) if p.as_char() == '>' && !is_arrow_end => {
                    angles = angles.saturating_sub(1);
                }
                TokenTree::Ident(ref name) if container && !item_body => {
                    match name.to_string().as_str() {
                        "mod" | "impl" | "trait" | "extern" => {
                            item_body = true;
                            item_container = true;
                        }
                        "fn" | "struct" | "enum" | "union" | "macro_rules" => item_body = true,
                        _ => {}
                    }
                }
                TokenTree::Group(group) => {
                    let brace = group.delimiter() == proc_macro2::Delimiter::Brace;
                    let child_container = brace && item_container;
                    let child_depth = structural_base + angles + 1;
                    if child_depth > structural_limit {
                        return Err(refuse("preparse structural depth limit exceeded"));
                    }
                    pending.push((
                        group.stream(),
                        if child_container { 0 } else { cost },
                        child_container,
                        child_depth,
                    ));
                    if brace && container && item_body {
                        cost = base;
                        item_body = false;
                        item_container = false;
                    }
                }
                TokenTree::Punct(p) if p.as_char() == ';' || p.as_char() == ',' => {
                    if p.as_char() == ';' {
                        angles = 0;
                    }
                    cost = base + angles;
                    item_body = false;
                    item_container = false;
                }
                _ => {}
            }
        }
    }
    Ok(())
}

struct InventoryVisitor<'src> {
    source: &'src str,
    lines: Vec<usize>,
    limits: Limits,
    nodes: Vec<Node>,
    parents: Vec<usize>,
    error: Option<Error>,
}
impl InventoryVisitor<'_> {
    fn range(&self, range: std::ops::Range<usize>) -> Result<SourceSpan, Error> {
        if range.start > range.end
            || range.end > self.source.len()
            || !self.source.is_char_boundary(range.start)
            || !self.source.is_char_boundary(range.end)
        {
            return Err(refuse("invalid source byte span"));
        }
        let position = |offset| {
            let line = self.lines.partition_point(|start| *start <= offset) - 1;
            Position {
                line: line + 1,
                byte_column: offset - self.lines[line],
            }
        };
        Ok(SourceSpan {
            line_byte_column_range: LineByteColumnRange {
                start: position(range.start),
                end: position(range.end),
            },
            byte_range: ByteRange {
                start: range.start,
                end: range.end,
            },
        })
    }
    fn span(&mut self, span: Span) -> Option<SourceSpan> {
        match self.range(span.byte_range()) {
            Ok(span) => Some(span),
            Err(error) => {
                self.error = Some(error);
                None
            }
        }
    }
    fn enter_range(&mut self, kind: &'static str, range: std::ops::Range<usize>) -> bool {
        if self.error.is_some() {
            return false;
        }
        if self.nodes.len() >= self.limits.max_nodes || self.parents.len() >= self.limits.max_depth
        {
            self.error = Some(refuse("node count or ancestry depth limit exceeded"));
            return false;
        }
        let span = match self.range(range) {
            Ok(span) => span,
            Err(error) => {
                self.error = Some(error);
                return false;
            }
        };
        let id = self.nodes.len();
        self.nodes.push(Node {
            id,
            parent: self.parents.last().copied(),
            kind,
            span,
            name: None,
            attributes: Vec::new(),
            signature: None,
            parameters: Vec::new(),
            body: None,
            roles: Vec::new(),
            opaque: false,
        });
        self.parents.push(id);
        true
    }
    fn enter(&mut self, kind: &'static str, span: Span) -> bool {
        self.enter_range(kind, span.byte_range())
    }
    fn leave(&mut self) {
        self.parents.pop();
    }
    fn current(&mut self) -> &mut Node {
        let id = self.parents[self.parents.len() - 1];
        &mut self.nodes[id]
    }
    fn role(&mut self, role: &'static str, span: Span) {
        if let Some(span) = self.span(span) {
            self.current().roles.push(Role { role, span });
        }
    }
    fn attributes(&mut self, attributes: &[syn::Attribute]) {
        for attribute in attributes {
            if let Some(span) = self.span(attribute.span()) {
                self.current().attributes.push(span);
            }
        }
    }
    fn function(&mut self, signature: &syn::Signature, body: Option<&syn::Block>) {
        self.current().name = Some(signature.ident.to_string());
        self.current().signature = self.span(signature.span());
        for parameter in &signature.inputs {
            if let Some(span) = self.span(parameter.span()) {
                self.current().parameters.push(span);
            }
        }
        self.current().body = body.and_then(|b| self.span(b.span()));
    }
}
impl<'ast> Visit<'ast> for InventoryVisitor<'_> {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        let (kind, name, attrs) = match item {
            syn::Item::Mod(v) => ("module", Some(v.ident.to_string()), v.attrs.as_slice()),
            syn::Item::Fn(v) => ("fn", Some(v.sig.ident.to_string()), v.attrs.as_slice()),
            syn::Item::Impl(v) => ("impl", None, v.attrs.as_slice()),
            syn::Item::Trait(v) => ("trait", Some(v.ident.to_string()), v.attrs.as_slice()),
            syn::Item::Struct(v) => ("struct", Some(v.ident.to_string()), v.attrs.as_slice()),
            syn::Item::Enum(v) => ("enum", Some(v.ident.to_string()), v.attrs.as_slice()),
            syn::Item::Type(v) => ("type", Some(v.ident.to_string()), v.attrs.as_slice()),
            syn::Item::Macro(v) => (
                "macro",
                v.ident.as_ref().map(ToString::to_string),
                v.attrs.as_slice(),
            ),
            _ => ("other_item", None, &[][..]),
        };
        if !self.enter(kind, item.span()) {
            return;
        }
        self.current().name = name;
        self.attributes(attrs);
        match item {
            syn::Item::Fn(v) => self.function(&v.sig, Some(&v.block)),
            syn::Item::Impl(v) => {
                self.current().body = self.span(v.brace_token.span.join());
                self.role("self_type", v.self_ty.span());
                if let Some((_, path, _)) = &v.trait_ {
                    self.role("trait_path", path.span());
                }
            }
            syn::Item::Mod(v) => {
                if let Some((brace, _)) = &v.content {
                    self.current().body = self.span(brace.span.join());
                }
            }
            syn::Item::Trait(v) => self.current().body = self.span(v.brace_token.span.join()),
            syn::Item::Enum(v) => self.current().body = self.span(v.brace_token.span.join()),
            syn::Item::Struct(v) => {
                self.current().body = match &v.fields {
                    syn::Fields::Named(fields) => self.span(fields.brace_token.span.join()),
                    syn::Fields::Unnamed(fields) => self.span(fields.paren_token.span.join()),
                    syn::Fields::Unit => None,
                };
            }
            syn::Item::Macro(v) => {
                self.current().opaque = true;
                self.role("macro_tokens", v.mac.delimiter.span().join());
            }
            _ => {}
        }
        if kind == "other_item" {
            self.current().opaque = true;
        }
        visit::visit_item(self, item);
        self.leave();
    }
    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        let kind = match item {
            syn::ImplItem::Fn(_) => "impl_fn",
            syn::ImplItem::Macro(_) => "macro",
            syn::ImplItem::Type(_) => "type",
            _ => "other_impl_item",
        };
        if !self.enter(kind, item.span()) {
            return;
        }
        match item {
            syn::ImplItem::Fn(v) => {
                self.function(&v.sig, Some(&v.block));
                self.attributes(&v.attrs);
            }
            syn::ImplItem::Macro(v) => {
                self.current().opaque = true;
                self.attributes(&v.attrs);
                self.role("macro_tokens", v.mac.delimiter.span().join());
            }
            syn::ImplItem::Type(v) => {
                self.current().name = Some(v.ident.to_string());
                self.attributes(&v.attrs);
            }
            _ => self.current().opaque = true,
        }
        visit::visit_impl_item(self, item);
        self.leave();
    }
    fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
        let kind = match item {
            syn::TraitItem::Fn(_) => "trait_fn",
            syn::TraitItem::Macro(_) => "macro",
            syn::TraitItem::Type(_) => "type",
            _ => "other_trait_item",
        };
        if !self.enter(kind, item.span()) {
            return;
        }
        match item {
            syn::TraitItem::Fn(v) => {
                self.function(&v.sig, v.default.as_ref());
                self.attributes(&v.attrs);
            }
            syn::TraitItem::Macro(v) => {
                self.current().opaque = true;
                self.attributes(&v.attrs);
                self.role("macro_tokens", v.mac.delimiter.span().join());
            }
            syn::TraitItem::Type(v) => {
                self.current().name = Some(v.ident.to_string());
                self.attributes(&v.attrs);
            }
            _ => self.current().opaque = true,
        }
        visit::visit_trait_item(self, item);
        self.leave();
    }
    fn visit_attribute(&mut self, attribute: &'ast syn::Attribute) {
        if !self.enter("attribute", attribute.span()) {
            return;
        }
        self.current().opaque = true;
        // Attribute token trees are retained by span, never interpreted or expanded.
        self.leave();
    }
    fn visit_block(&mut self, block: &'ast syn::Block) {
        if !self.enter("block", block.span()) {
            return;
        }
        visit::visit_block(self, block);
        self.leave();
    }
    fn visit_stmt_macro(&mut self, statement: &'ast syn::StmtMacro) {
        if !self.enter("macro", statement.span()) {
            return;
        }
        self.current().opaque = true;
        self.attributes(&statement.attrs);
        self.role("macro_tokens", statement.mac.delimiter.span().join());
        visit::visit_stmt_macro(self, statement);
        self.leave();
    }
    fn visit_local(&mut self, local: &'ast syn::Local) {
        if !self.enter("local", local.span()) {
            return;
        }
        self.attributes(&local.attrs);
        self.role("pattern", local.pat.span());
        if let Some(init) = &local.init {
            self.role("initializer", init.expr.span());
            if let Some((_, expr)) = &init.diverge {
                self.role("else_branch", expr.span());
            }
        }
        visit::visit_local(self, local);
        self.leave();
    }
    fn visit_expr(&mut self, expr: &'ast syn::Expr) {
        let kind = match expr {
            syn::Expr::If(_) => "if",
            syn::Expr::ForLoop(_) => "for",
            syn::Expr::While(_) => "while",
            syn::Expr::Loop(_) => "loop",
            syn::Expr::Closure(_) => "closure",
            syn::Expr::Async(_) => "async",
            syn::Expr::Call(_) => "call",
            syn::Expr::MethodCall(_) => "method_call",
            syn::Expr::Try(_) => "try",
            syn::Expr::Return(_) => "return",
            syn::Expr::Let(_) => "let",
            syn::Expr::Path(_) => "path",
            syn::Expr::Macro(_) => "macro",
            syn::Expr::Match(_) => "match",
            syn::Expr::Block(_) => "block_expr",
            syn::Expr::Await(_) => "await",
            syn::Expr::Break(_) => "break",
            syn::Expr::Continue(_) => "continue",
            syn::Expr::Verbatim(_) => "opaque_expr",
            _ => "expression",
        };
        if !self.enter(kind, expr.span()) {
            return;
        }
        match expr {
            syn::Expr::If(v) => {
                self.role("condition", v.cond.span());
                self.role("then_branch", v.then_branch.span());
                if let Some((_, e)) = &v.else_branch {
                    self.role("else_branch", e.span());
                }
            }
            syn::Expr::ForLoop(v) => {
                self.role("pattern", v.pat.span());
                self.role("iterator", v.expr.span());
                self.role("body", v.body.span());
            }
            syn::Expr::While(v) => {
                self.role("condition", v.cond.span());
                self.role("body", v.body.span());
            }
            syn::Expr::Loop(v) => self.role("body", v.body.span()),
            syn::Expr::Closure(v) => {
                self.role("body", v.body.span());
                self.current().body = self.span(v.body.span());
                for p in &v.inputs {
                    if let Some(span) = self.span(p.span()) {
                        self.current().parameters.push(span);
                    }
                }
            }
            syn::Expr::Async(v) => {
                self.role("body", v.block.span());
                self.current().body = self.span(v.block.span());
            }
            syn::Expr::Call(v) => {
                self.role("callee", v.func.span());
                for a in &v.args {
                    self.role("argument", a.span());
                }
            }
            syn::Expr::MethodCall(v) => {
                self.current().name = Some(v.method.to_string());
                self.role("receiver", v.receiver.span());
                self.role("method", v.method.span());
                for a in &v.args {
                    self.role("argument", a.span());
                }
            }
            syn::Expr::Try(v) => {
                self.role("operand", v.expr.span());
                self.role("question_mark", v.question_token.span());
            }
            syn::Expr::Return(v) => {
                if let Some(e) = &v.expr {
                    self.role("value", e.span());
                }
            }
            syn::Expr::Let(v) => {
                self.role("pattern", v.pat.span());
                self.role("value", v.expr.span());
            }
            syn::Expr::Macro(v) => {
                self.current().opaque = true;
                self.role("macro_tokens", v.mac.delimiter.span().join());
            }
            syn::Expr::Verbatim(_) => self.current().opaque = true,
            _ => {}
        }
        visit::visit_expr(self, expr);
        self.leave();
    }
}
