use coverage_source_inventory::{Limits, inventory, inventory_with_limits};

fn json(source: &str) -> serde_json::Value {
    serde_json::to_value(inventory(source).expect("valid fixture")).expect("serialize")
}
fn nodes(value: &serde_json::Value) -> &[serde_json::Value] {
    value["nodes"].as_array().expect("nodes")
}
fn kind<'a>(value: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    nodes(value)
        .iter()
        .find(|n| n["kind"] == name)
        .expect("kind exists")
}
fn text<'a>(source: &'a str, node: &serde_json::Value) -> &'a str {
    let range = &node["span"]["byte_range"];
    &source[range["start"].as_u64().expect("start") as usize
        ..range["end"].as_u64().expect("end") as usize]
}
#[test]
fn multiline_headers_modules_and_methods() {
    let source = "mod outer {\nstruct S;\nimpl S {\n pub async fn run(\n &self,\n n: usize,\n ) -> usize { n }\n}\ntrait T { fn pending(&self); }\nenum E { A }\ntype Alias = S;\n}";
    let value = json(source);
    let method = kind(&value, "impl_fn");
    assert!(text(source, method).starts_with("pub async fn run"));
    assert_eq!(
        method["parameters"].as_array().expect("parameters").len(),
        2
    );
    assert_eq!(method["parent"], kind(&value, "impl")["id"]);
    assert_eq!(kind(&value, "impl")["parent"], kind(&value, "module")["id"]);
    assert!(method["signature"].is_object());
    assert!(method["body"].is_object());
    assert!(kind(&value, "trait_fn")["body"].is_null());
    for name in ["struct", "enum", "type", "trait"] {
        kind(&value, name);
    }
    assert_eq!(value, json(source), "stable IDs and serialization");
}
#[test]
fn unicode_byte_columns_and_endpoints() {
    let source = "fn café() { let é = 1; é; } struct S;";
    let value = json(source);
    let structure = kind(&value, "struct");
    assert_eq!(
        structure["span"]["line_byte_column_range"]["start"]["byte_column"].as_u64(),
        Some(source.find("struct").expect("struct") as u64)
    );
    let function = kind(&value, "fn");
    assert_eq!(text(source, function), "fn café() { let é = 1; é; }");
    assert!(function["span"]["byte_range"]["end"] != structure["span"]["byte_range"]["end"]);
}
#[test]
fn comments_raw_strings_and_macros_are_opaque() {
    let source = "// fn fake() {}\nfn real() { let s = r###\"fn fake2() {} /* () */\"###; maker!(fn hidden() {}); }\nmacro_rules! maker { ($x:tt) => { fn generated() {} } }";
    let value = json(source);
    assert_eq!(
        nodes(&value).iter().filter(|n| n["kind"] == "fn").count(),
        1
    );
    let macros: Vec<_> = nodes(&value)
        .iter()
        .filter(|n| n["kind"] == "macro")
        .collect();
    assert_eq!(macros.len(), 2);
    assert!(macros.iter().all(|n| n["opaque"] == true));
    assert!(text(source, macros[1]).contains("generated"));
}
#[test]
fn conditional_duplicates_and_unknown_attributes_are_retained() {
    let source = "#[cfg(unix)] fn f() {} #[cfg(windows)] fn f() {} #[mystery(x)] struct S;";
    let value = json(source);
    let functions: Vec<_> = nodes(&value).iter().filter(|n| n["kind"] == "fn").collect();
    assert_eq!(functions.len(), 2);
    assert_ne!(functions[0]["id"], functions[1]["id"]);
    assert!(
        nodes(&value)
            .iter()
            .filter(|n| n["kind"] == "attribute")
            .all(|n| n["opaque"] == true)
    );
    assert_eq!(
        functions[0]["attributes"].as_array().expect("attrs").len(),
        1
    );
    assert!(value["acceptance"] == false);
}
#[test]
fn exclusive_alternatives_and_call_try_closure_roles() {
    let source = "fn f() { if let Some(handle) = get() { return handle; } fallback(); for x in xs { (|v| { if v { act(); } })(x); } prepare().map_err(|e| { refuse(e) })?; async { work().await }; }";
    let value = json(source);
    let conditional = kind(&value, "if");
    let returned = kind(&value, "return");
    let parent = nodes(&value)
        .iter()
        .find(|n| n["id"] == returned["parent"])
        .expect("return parent");
    assert_eq!(parent["parent"], conditional["id"]);
    assert!(
        conditional["roles"]
            .as_array()
            .expect("roles")
            .iter()
            .any(|r| r["role"] == "condition")
    );
    let closure = nodes(&value)
        .iter()
        .rfind(|n| n["kind"] == "closure")
        .expect("map closure");
    assert_eq!(closure["parent"], kind(&value, "method_call")["id"]);
    assert_eq!(
        kind(&value, "method_call")["parent"],
        kind(&value, "try")["id"]
    );
    let try_roles = kind(&value, "try")["roles"].as_array().expect("try roles");
    assert!(try_roles.iter().any(|r| r["role"] == "question_mark"));
    for name in ["for", "async", "call", "let", "path"] {
        kind(&value, name);
    }
    for node in nodes(&value) {
        let _ = text(source, node);
        if let Some(id) = node["parent"].as_u64() {
            assert!(id < node["id"].as_u64().expect("id"));
        }
    }
}
#[test]
fn failures_and_resource_bounds_refuse() {
    assert!(inventory("fn broken(").is_err());
    assert!(inventory(&" ".repeat(1_048_577)).is_err());
    assert!(
        inventory(&format!(
            "fn f() {{ {}1{} }}",
            "(".repeat(129),
            ")".repeat(129)
        ))
        .is_err()
    );
    assert!(inventory(&format!("fn f() {{ {}true; }}", "!".repeat(100_000))).is_err());
    let source = "fn f() { a(); b(); }";
    assert!(
        inventory_with_limits(
            source,
            Limits {
                max_nodes: 2,
                ..Limits::default()
            }
        )
        .is_err()
    );
    assert!(
        inventory_with_limits(
            source,
            Limits {
                max_output_bytes: 10,
                ..Limits::default()
            }
        )
        .is_err()
    );
    assert!(
        inventory_with_limits(
            source,
            Limits {
                max_depth: 2,
                ..Limits::default()
            }
        )
        .is_err()
    );
}

#[test]
fn wide_files_do_not_exhaust_depth_and_raw_literals_do_not_create_nesting() {
    let source = (0..300)
        .map(|n| format!("fn f{n}() {{}}\n"))
        .collect::<String>();
    assert_eq!(
        nodes(&json(&source))
            .iter()
            .filter(|n| n["kind"] == "fn")
            .count(),
        300
    );
    let source = format!(
        "fn f() {{ let raw = r###\"{}\"###; let ch = '{{'; }}",
        "{".repeat(200)
    );
    inventory(&source).expect("literal delimiters are not nesting");
    inventory("#!/usr/bin/env rust-script\nfn main() {} ").expect("shebang is preserved");
}

#[test]
fn every_recorded_span_has_valid_original_source_ancestry() {
    let source = "//! crate docs\n#[custom] mod inner { /// café docs\nfn café() { empty!(); #[cfg(unix)] { go(); } } }";
    let value = json(source);
    for node in nodes(&value) {
        let start = node["span"]["byte_range"]["start"].as_u64().expect("start");
        let end = node["span"]["byte_range"]["end"].as_u64().expect("end");
        if let Some(parent) = node["parent"].as_u64() {
            let ancestor = &nodes(&value)[parent as usize];
            assert!(
                start
                    >= ancestor["span"]["byte_range"]["start"]
                        .as_u64()
                        .expect("parent start"),
                "{node}"
            );
            assert!(
                end <= ancestor["span"]["byte_range"]["end"]
                    .as_u64()
                    .expect("parent end"),
                "{node}"
            );
        }
        for role in node["roles"].as_array().expect("roles") {
            assert!(
                role["span"]["byte_range"]["start"]
                    .as_u64()
                    .expect("role start")
                    >= start,
                "{role}"
            );
            assert!(
                role["span"]["byte_range"]["end"]
                    .as_u64()
                    .expect("role end")
                    <= end,
                "{role}"
            );
        }
    }
}

#[test]
fn actual_callback_complexity_is_supported_but_structural_depth_refuses() {
    let actual = include_str!("fixtures/alpm-question-callback.rs");
    let value = json(actual);
    assert_eq!(kind(&value, "fn")["name"], "setup_alpm_callbacks");
    assert!(
        nodes(&value)
            .iter()
            .any(|n| n["kind"] == "method_call" && n["name"] == "with_prompt")
    );
    let nested = format!(
        "fn f() {{ {}true{} }}",
        "if true {".repeat(120),
        "}".repeat(120)
    );
    assert!(
        inventory(&nested).is_err(),
        "nested control ancestry must refuse"
    );
    let chain = format!(
        "const X: bool = {}true;",
        "if true {{}} else ".repeat(10_000)
    );
    assert!(
        inventory(&chain).is_err(),
        "delimiter-free control chain must refuse"
    );
}

#[test]
fn declared_container_bodies_have_explicit_spans() {
    let value =
        json("mod m { struct S { a: u8 } enum E { A } trait T { fn f(); } impl S { fn f() {} } }");
    for name in ["module", "struct", "enum", "trait", "impl"] {
        assert!(
            kind(&value, name)["body"].is_object(),
            "body required for {name}"
        );
    }
}

#[test]
fn generic_separators_and_arrows_preserve_recursion_bounds() {
    for source in [
        format!(
            "type T = {}u8{};",
            "A<u8,".repeat(1000),
            ",u8>".repeat(1000)
        ),
        format!(
            "fn f() {{ call::<{}u8{}>(); }}",
            "A<u8,".repeat(1000),
            ",u8>".repeat(1000)
        ),
        format!(
            "type T = {}u8{};",
            "A<u8, fn() -> ".repeat(1000),
            ">".repeat(1000)
        ),
        format!("type T = {}u8{};", "A<(".repeat(100), ",u8)>".repeat(100)),
    ] {
        assert!(
            inventory(&source).is_err(),
            "recursive type path must refuse before syn"
        );
    }
    inventory(&format!("type T = A<{}u8>;", "u8,".repeat(3000)))
        .expect("wide shallow type arguments");
    inventory("type T = A<fn() -> B<u8>>;").expect("ordinary nested arrow type");
}
#[test]
fn shebang_quotes_do_not_hide_later_lexical_nesting() {
    let source = format!(
        "#!\"\nmacro_rules! m {{ {}x{} }}",
        "(".repeat(200),
        ")".repeat(200)
    );
    assert!(
        inventory(&source).is_err(),
        "quoted shebang must not suppress depth guard"
    );
    let source = "#!\"\nfn real() {}";
    let value = json(source);
    assert_eq!(text(source, kind(&value, "fn")), "fn real() {}");
    assert_eq!(kind(&value, "fn")["span"]["byte_range"]["start"], 4);
}

#[test]
fn bom_and_shebang_masking_preserve_original_byte_offsets() {
    for source in [
        "\u{feff}fn real() {}",
        "\u{feff}#!\"\nfn real() {}",
        "#!/usr/bin/env rust-script\nfn real() {}",
    ] {
        let value = json(source);
        assert_eq!(text(source, kind(&value, "fn")), "fn real() {}");
        assert_eq!(
            kind(&value, "fn")["span"]["byte_range"]["start"].as_u64(),
            Some(source.find("fn real").expect("fn") as u64)
        );
    }
}
