//! Allocation regression for the production completion path, in its own process.
use std::alloc::System;

use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};

use omg_lib::core::completion::CompletionEngine;

#[global_allocator]
static ALLOCATOR: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn fuzzy_ranking_allocations_grow_with_candidates() {
    let engine = CompletionEngine::new();
    for count in [4096, 32768] {
        // Varied prefix/nonprefix, mixed case and Unicode, deterministically shuffled.
        let candidates: Vec<String> = (0..count)
            .map(|i| {
                let id = (i * 7919) % count;
                match id % 4 {
                    0 => format!("Pkg-{id:06}"),
                    1 => format!("prefix-pkg-{id:06}-tools"),
                    2 => format!("pkg-{id:06}-é"),
                    _ => format!("x-p-k-g-{id:06}"),
                }
            })
            .collect();
        let region = Region::new(ALLOCATOR);
        let ranked = engine.fuzzy_match("pkg", candidates);
        let stats = region.change();
        let allocations = stats.allocations + stats.reallocations;
        println!(
            "candidates={count} matches={} allocations={allocations} allocated_bytes={} reallocated_bytes_delta={}",
            ranked.len(),
            stats.bytes_allocated,
            stats.bytes_reallocated
        );
        assert_eq!(ranked.len(), count);
        // Scoring may allocate a UTF32 buffer per candidate. Collection growth,
        // matcher/pattern setup and stable sort require additional allocations.
        // Two allocations per comparison exceed this linear resource budget.
        assert!(
            allocations <= 2 * count + 128,
            "{allocations} allocations for {count} candidates"
        );
    }
    let candidates = vec!["z".to_owned(), "a".to_owned()];
    assert_eq!(engine.fuzzy_match("", candidates), ["z", "a"]);
    assert!(
        engine
            .fuzzy_match("absent", vec!["pkg".to_owned()])
            .is_empty()
    );
}
