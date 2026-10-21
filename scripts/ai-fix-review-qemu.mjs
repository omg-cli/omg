import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";

const command = promisify(execFile);
const prefix = "/repos/omg-cli/omg";
const distros = ["arch", "debian", "debian-trixie", "ubuntu", "fedora"];

export function admitQemuRun(run, headSha) {
    if (run.repository?.full_name !== "omg-cli/omg" || run.path !== ".github/workflows/ci.yml" ||
        run.event !== "pull_request" || run.head_sha !== headSha || run.conclusion !== "success" ||
        run.status !== "completed" || !Number.isSafeInteger(run.id) || run.id < 1 ||
        !Number.isSafeInteger(run.run_attempt) || run.run_attempt < 1)
        throw new Error("QEMU CI producer does not bind this exact PR head.");
}

export function admitQemuSource(commit, { headSha, baseSha, headTreeSha }) {
    if (commit.tree?.sha !== headTreeSha || (commit.sha !== headSha &&
        (commit.parents?.length !== 2 || commit.parents[0].sha !== baseSha || commit.parents[1].sha !== headSha)))
        throw new Error("QEMU compiled source tree differs from the exact published repair.");
}

// Only trusted parser code runs. ZIP members are bounded data and are never extracted or executed.
const inspectArchive = String.raw`
import importlib.util,io,json,pathlib,re,sys,tempfile,zipfile
spec=importlib.util.spec_from_file_location('qemu_report',pathlib.Path('scripts/report-qemu-workflow.py'))
report=importlib.util.module_from_spec(spec);spec.loader.exec_module(report)
file,distro,head,run_id=sys.argv[1:]
content=pathlib.Path(file).read_bytes()
_,snapshots=report.all_snapshots(pathlib.Path('tests/qemu-inventory-policy.json'))
with zipfile.ZipFile(io.BytesIO(content)) as archive:
 def read(name):
  members=[member for member in archive.infolist() if member.filename==name]
  if len(members)!=1 or members[0].file_size>1024*1024:raise ValueError('missing bounded QEMU evidence')
  return archive.read(members[0])
 provenance=json.loads(read('provenance.json'),object_pairs_hook=report.unique_object)
 native=provenance.get('native_build',{})
 source=provenance.get('harness_revision','')
 if not re.fullmatch('[a-f0-9]{40}',source) or provenance.get('staged') is not True or native.get('source_sha')!=source or native.get('repository')!='omg-cli/omg' or str(native.get('run_id'))!=run_id or native.get('workflow_path')!='.github/workflows/ci.yml' or native.get('distro')!=distro or native.get('profile')!='release' or native.get('instrumentation')!='none':raise ValueError('QEMU native source mismatch')
 rows=report.archive_rows(content,report.canonical_case_ids({'inventories':snapshots}),guest=(distro,'x86_64'),revision=source)
 if not rows or any(row['result'] in report.FAILURES for row in rows):raise ValueError('QEMU failed or absent rows')
 admissions=[member.filename for member in archive.infolist() if member.filename.endswith('/inventory-admission.json')]
 if len(admissions)!=1:raise ValueError('QEMU inventory admission missing')
 root=admissions[0].rsplit('/',1)[0]
 inputs={'inventory':read(root+'/cases.tsv'),'results':read(root+'/inventory/results.json'),'summary':read(root+'/inventory/summary.json')}
 claimed=json.loads(read(admissions[0]),object_pairs_hook=report.unique_object)
 spec=importlib.util.spec_from_file_location('qemu_admission',pathlib.Path('scripts/check-qemu-inventory.py'))
 checker=importlib.util.module_from_spec(spec);spec.loader.exec_module(checker)
 with tempfile.TemporaryDirectory() as directory:
  paths={key:pathlib.Path(directory)/key for key in inputs}
  for key,data in inputs.items():paths[key].write_bytes(data)
  for name in ('input-sha256.txt','rows/doctor-network-live.stdout.log','rows/doctor-network-live.stderr.log'):
   destination=pathlib.Path(directory)/name;destination.parent.mkdir(parents=True,exist_ok=True)
   destination.write_bytes(read(root+'/inventory/'+name))
  admitted=checker.admit(pathlib.Path('tests/qemu-inventory-policy.json'),paths['inventory'],paths['results'],paths['summary'],distro,'hermetic,container,network')
 if json.dumps(admitted,sort_keys=True)!=json.dumps(claimed,sort_keys=True) or admitted.get('passed') is not True:raise ValueError('QEMU inventory admission differs')
print(json.dumps({'sourceSha':source}))
`;

export async function inspectQemuArchive({ file, distro, headSha, runId }) {
    const inspected = await command(process.platform === "win32" ? "python" : "python3",
        ["-c", inspectArchive, file, distro, headSha, String(runId)],
        { timeout: 60000, maxBuffer: 1024 * 1024, windowsHide: true });
    const { sourceSha } = JSON.parse(inspected.stdout);
    if (!/^[a-f0-9]{40}$/.test(sourceSha)) throw new Error("Invalid QEMU compiled source identity.");
    return sourceSha;
}

export async function admitQemuArtifacts({ github, checks, headSha, baseSha, headTreeSha }) {
    const check = checks.find((check) => check.name === "QEMU behavioral verification / QEMU matrix result");
    const identity = /^https:\/\/github\.com\/omg-cli\/omg\/actions\/runs\/([1-9][0-9]*)\/job\/[1-9][0-9]*$/.exec(check?.details_url ?? "");
    if (!identity) throw new Error("QEMU check lacks a trusted Actions run identity.");
    const route = `${prefix}/actions/runs/${identity[1]}`;
    const run = await github.request("GET", route);
    admitQemuRun(run, headSha);
    const artifacts = await github.request("GET", `${route}/artifacts?per_page=100`);
    if (!Array.isArray(artifacts.artifacts) || artifacts.total_count !== artifacts.artifacts.length)
        throw new Error("Incomplete QEMU artifact inventory.");
    const directory = await mkdtemp(path.join(tmpdir(), "omg-fix-review-qemu-"));
    try {
        for (const distro of distros) {
            const matches = artifacts.artifacts.filter((artifact) => artifact.name === `qemu-evidence-${distro}`);
            if (matches.length !== 1 || matches[0].expired || !Number.isSafeInteger(matches[0].id) ||
                matches[0].size_in_bytes > 16 * 1024 * 1024)
                throw new Error("Missing, expired or oversized QEMU guest artifact.");
            const artifact = matches[0];
            const { stdout } = await command("gh", ["api", "--hostname", "github.com", `${prefix}/actions/artifacts/${artifact.id}/zip`],
                { encoding: "buffer", timeout: 60000, maxBuffer: 16 * 1024 * 1024, windowsHide: true });
            const digest = `sha256:${createHash("sha256").update(stdout).digest("hex")}`;
            if (digest !== artifact.digest) throw new Error("QEMU artifact digest mismatch.");
            const file = path.join(directory, `${distro}.zip`);
            await writeFile(file, stdout, { flag: "wx", mode: 0o600 });
            const sourceSha = await inspectQemuArchive({ file, distro, headSha, runId: run.id });
            const source = await github.request("GET", `${prefix}/git/commits/${sourceSha}`);
            admitQemuSource(source, { headSha, baseSha, headTreeSha });
        }
        const fresh = await github.request("GET", route);
        admitQemuRun(fresh, headSha);
        if (fresh.run_attempt !== run.run_attempt) throw new Error("QEMU producer attempt changed during admission.");
    } finally {
        if (path.dirname(directory) !== path.resolve(tmpdir()) || !path.basename(directory).startsWith("omg-fix-review-qemu-"))
            throw new Error("Refusing to retire a directory outside the owned QEMU review scratch.");
        await rm(directory, { recursive: true, force: true });
    }
}
