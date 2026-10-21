import { CiSandbox as NativeCiSandbox } from "@cloudflare/ci/worker";
import { PhaseDiagnostics, type StopDetails } from "./phase-diagnostics";
import { backupTransferMode, leafSnapshotOptions } from "./backup-policy";
import { retainRunnerLog, retainUnitReport } from "./unit-report-retention";

type RunnerMetadata = {
  reportRunId?: string;
  diagnosticRunId?: string;
  leafStep?: string;
};
const metadataKey = "omg:runner-metadata";

export class CiSandbox extends NativeCiSandbox {
  private phases?: PhaseDiagnostics;
  private fuseExitCode?: number;
  private get diagnostics() {
    return (this.phases ??= new PhaseDiagnostics(this.ctx.id.toString(), (key, value) =>
      this.env.BACKUP_BUCKET.put(key, value, { httpMetadata: { contentType: "application/json" } }),
    ));
  }
  private trace<T>(
    phase: Parameters<PhaseDiagnostics["run"]>[0],
    operation: () => Promise<T>,
    stop?: StopDetails,
  ) {
    const result = this.diagnostics.run(phase, operation, stop);
    this.ctx.waitUntil(
      result.then(
        () => this.phases?.flush(),
        () => this.phases?.flush(),
      ),
    );

    return result;
  }
  override configure(configuration: Parameters<NativeCiSandbox["configure"]>[0]) {
    if (configuration.sandboxName) this.diagnostics.setRunner(configuration.sandboxName.name);

    return this.trace("configure", () => super.configure(configuration));
  }
  override exec(...args: Parameters<NativeCiSandbox["exec"]>) {
    const phase =
      args[0] === "test -c /dev/fuse"
        ? "preflight"
        : args[0].startsWith("tail -c ")
          ? "log-read"
          : "checkout";

    return this.trace(phase, async () => {
      const result = await super.exec(...args);

      if (phase === "preflight") {
        this.fuseExitCode = result.exitCode;
        this.diagnostics.setFuseExitCode(result.exitCode);
      }

      return result;
    });
  }
  override execWithSessionToken(...args: Parameters<NativeCiSandbox["execWithSessionToken"]>) {
    const phase =
      args[0] === "test -c /dev/fuse"
        ? "preflight"
        : args[0].startsWith("tail -c ")
          ? "log-read"
          : "checkout";

    return this.trace(phase, async () => {
      const result = await super.execWithSessionToken(...args);

      if (phase === "preflight") {
        this.fuseExitCode = result.exitCode;
        this.diagnostics.setFuseExitCode(result.exitCode);
      }

      return result;
    });
  }
  override restoreBackup(backup: Parameters<NativeCiSandbox["restoreBackup"]>[0]) {
    const localBucket = backupTransferMode(this.env) === "binding-rpc" || this.fuseExitCode !== 0;

    return this.trace("restore", () => super.restoreBackup({ ...backup, localBucket }));
  }

  override createBackup(options: Parameters<NativeCiSandbox["createBackup"]>[0]) {
    const localBucket = backupTransferMode(this.env) === "binding-rpc" ? true : options.localBucket;

    return this.trace("backup", async () => {
      const metadata = await this.ctx.storage.get<RunnerMetadata>(metadataKey);
      return super.createBackup({ ...options, localBucket, ...leafSnapshotOptions(metadata?.leafStep) });
    });
  }
  override startProcess(...args: Parameters<NativeCiSandbox["startProcess"]>) {
    const env = args[1]?.env;
    return this.trace("process-start", async () => {
      await this.ctx.storage.put<RunnerMetadata>(metadataKey, {
        reportRunId: env?.OMG_CI_LEAF_STEP === "rust-portable-tests" ? env?.OMG_REPORT_RUN_ID : undefined,
        leafStep: env?.OMG_CI_LEAF_STEP,
        diagnosticRunId: env?.OMG_DIAGNOSTIC_RUN_ID,
      });
      return super.startProcess(...args);
    });
  }
  override streamProcessLogs(...args: Parameters<NativeCiSandbox["streamProcessLogs"]>) {
    return this.trace("process-log-stream-open", () => super.streamProcessLogs(...args));
  }
  override readFileStream(...args: Parameters<NativeCiSandbox["readFileStream"]>) {
    return this.trace("log-read", () => super.readFileStream(...args));
  }
  override listFiles(...args: Parameters<NativeCiSandbox["listFiles"]>) {
    return this.trace("log-list", () => super.listFiles(...args));
  }
  override onStop(stop?: StopDetails) {
    return this.trace("stop", () => super.onStop(stop), stop);
  }
  override onActivityExpired() {
    return this.trace("activity-expired", () => super.onActivityExpired());
  }
  override destroy() {
    return this.trace("destroy", async () => {
      try {
        const metadata = await this.ctx.storage.get<RunnerMetadata>(metadataKey);
        if (metadata?.diagnosticRunId && metadata.leafStep) {
          for (const stream of ["stdout", "stderr"]) {
            const status = await retainRunnerLog(metadata.diagnosticRunId, metadata.leafStep, stream, {
              listFiles: (path) => super.listFiles(path),
              readReport: async () => (
                await super.readFile(`/tmp/ci-step.${stream === "stdout" ? "out" : "err"}`, {
                  encoding: "none",
                })
              ).content,
            }, this.env.BACKUP_BUCKET);
            if (status !== "saved")
              console.warn(JSON.stringify({ event: "runner_log_unavailable", stream, status }));
          }
        }
        if (metadata?.reportRunId) {
          const status = await retainUnitReport(
            metadata.reportRunId,
            {
              listFiles: (path) => super.listFiles(path),
              readReport: async () =>
                (
                  await super.readFile("/tmp/omg-ci-unit-evidence/report.xml", {
                    encoding: "none",
                  })
                ).content,
            },
            this.env.BACKUP_BUCKET,
          );

          if (status !== "saved")
            console.warn(JSON.stringify({ event: "unit_report_unavailable", status }));
        }
      } finally {
        await super.destroy();
      }
    });
  }
}
