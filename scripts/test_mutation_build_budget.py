"""Measure nested Cargo concurrency using the mutation job's actual environment."""
import concurrent.futures
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BUILD_SCRIPT = r'''
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::time::Duration;

fn update(delta: i32) {
    let path = std::env::var("OMG_BUILD_BUDGET_LEDGER").unwrap();
    let mut file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path).unwrap();
    file.lock().unwrap();
    let mut text = String::new();
    file.read_to_string(&mut text).unwrap();
    let values: Vec<u32> = text.split_whitespace().map(|word| word.parse().unwrap()).collect();
    let (current, peak, finished) = if values.is_empty() { (0_u32, 0_u32, 0_u32) } else { (values[0], values[1], values[2]) };
    let next = if delta > 0 { current.checked_add(1).unwrap() } else { current.checked_sub(1).unwrap() };
    file.seek(SeekFrom::Start(0)).unwrap();
    file.set_len(0).unwrap();
    write!(file, "{} {} {}", next, peak.max(next), finished + if delta < 0 { 1 } else { 0 }).unwrap();
    file.flush().unwrap();
    file.unlock().unwrap();
}

fn main() {
    println!("cargo:rerun-if-env-changed=OMG_BUILD_BUDGET_PHASE");
    if std::env::var("OMG_BUILD_BUDGET_PHASE").unwrap() == "measure" {
        update(1);
        std::thread::sleep(Duration::from_millis(1500));
        update(-1);
    }
}
'''


class MutationBuildBudget(unittest.TestCase):
    def test_two_mutation_workers_keep_nested_cargo_jobs_within_four_slots(self):
        workflow = (ROOT / '.github/workflows/mutation.yml').read_text()
        job = workflow.split('  mutation:\n', 1)[1].split('  mutation-result:\n', 1)[0]
        header = job.split('    steps:\n', 1)[0]
        match = re.search(r'^      CARGO_BUILD_JOBS: ["\']?(\d+)["\']?\s*$', header, re.M)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ledger = root / 'ledger'
            workers = []
            for worker in range(2):
                base = root / f'worker-{worker}'
                (base / 'src').mkdir(parents=True)
                (base / '.cargo').mkdir()
                (base / '.cargo/config.toml').write_bytes((ROOT / '.cargo/config.toml').read_bytes())
                dependencies = []
                for leaf in range(5):
                    name = f'leaf_{leaf}'
                    crate = base / name
                    (crate / 'src').mkdir(parents=True)
                    (crate / 'Cargo.toml').write_text(f'[package]\nname="{name}"\nversion="0.0.0"\nedition="2024"\n')
                    (crate / 'src/lib.rs').write_text('pub fn value() -> u8 { 1 }\n')
                    (crate / 'build.rs').write_text(BUILD_SCRIPT)
                    dependencies.append(f'{name} = {{ path="{name}" }}')
                (base / 'Cargo.toml').write_text('[package]\nname="probe"\nversion="0.0.0"\nedition="2024"\n[dependencies]\n' + '\n'.join(dependencies) + '\n')
                (base / 'src/lib.rs').write_text('pub fn value() -> u8 { 1 }\n')
                environment = dict(os.environ, CARGO_TARGET_DIR=str(base / 'target'),
                                   OMG_BUILD_BUDGET_LEDGER=str(ledger), CARGO_INCREMENTAL='0')
                environment.pop('CARGO_BUILD_JOBS', None)
                if match:
                    environment['CARGO_BUILD_JOBS'] = match[1]
                workers.append((base, environment))

            def build(worker, phase):
                base, environment = worker
                result = subprocess.run(['cargo', 'build', '--offline'], cwd=base,
                                        env=dict(environment, OMG_BUILD_BUDGET_PHASE=phase),
                                        capture_output=True, text=True, timeout=90, check=False)
                self.assertEqual(result.returncode, 0, result.stderr)

            for phase in ('warmup', 'measure'):
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                    list(pool.map(lambda worker: build(worker, phase), workers))
            current, peak, finished = map(int, ledger.read_text().split())
        self.assertEqual(current, 0, 'all build-script slots must be released')
        self.assertEqual(finished, 10, 'both Cargo trees must execute all five dependencies')
        print(f'Mutation nested build slots: peak={peak}, completed={finished}', flush=True)
        self.assertLessEqual(peak, 4, 'two mutation workers must not inherit five Cargo jobs each')


if __name__ == '__main__':
    unittest.main()
