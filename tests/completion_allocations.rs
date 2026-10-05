//! Allocation regression for the production completion path, in its own process.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use omg_lib::core::completion::CompletionEngine;

struct CountingAllocator;
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

// SAFETY: Every operation delegates the unchanged pointer/layout to System.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: The caller supplies the GlobalAlloc layout contract.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: The caller supplies the original allocated pointer/layout.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: The caller supplies the GlobalAlloc realloc contract.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

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
        let before = ALLOCATIONS.load(Ordering::Relaxed);
        let ranked = engine.fuzzy_match("pkg", candidates);
        let allocations = ALLOCATIONS.load(Ordering::Relaxed) - before;
        println!(
            "candidates={count} matches={} allocations={allocations}",
            ranked.len()
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
