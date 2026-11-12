use std::io::{self, Read, Write};

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().lock().take(1_048_577).read_to_end(&mut input)?;
    if input.len() > 1_048_576 {
        return Err(io::Error::other("input byte limit exceeded").into());
    }
    let source = std::str::from_utf8(&input)?;
    let facts = coverage_source_inventory::inventory(source)?;
    let encoded = serde_json::to_vec(&facts)?;
    io::stdout().lock().write_all(&encoded)?;
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("inventory refused: {error}");
        std::process::exit(1);
    }
}
