import { CiSandbox as NativeCiSandbox } from "@cloudflare/ci/worker";
import { PhaseDiagnostics, type StopDetails } from "./phase-diagnostics";
import { backupTransferMode, leafSnapshotOptions } from "./backup-policy";
import {
  releaseTerminalOwner,
  retainRunnerLog,
  retainSandboxEvidence,
  retainUnitReport,
  runIdPattern,
} from "./unit-report-retention";

type RunnerMetadata = {
  reportRunId?: string;
  diagnosticRunId?: string;
  leafStep?: string;
};
const metadataKey = "omg:runner-metadata";
const teardownKey = "omg:runner-teardown";

export class CiSandbox extends NativeCiSandbox {
  private phases?: PhaseDiagnostics;
  private fuseExitCode?: number;
  private cleanupOwner?: string;
  private teardown = false;

  constructor(...args: ConstructorParameters<typeof NativeCiSandbox>) {
    super(...args);
    void this.ctx.blockConcurrencyWhile(async () => {
      this.teardown = (await this.ctx.storage.get<boolean>(teardownKey)) === true;
    });
  }

  private assertStartAllowed() {
    if (this.teardown) throw new Error("Runner teardown refuses container start");

    if (this.cleanupOwner)
      throw new Error(`Sandbox is releasing terminal owner ${this.cleanupOwner}`);
  }

  protected override beforeStart() {
    this.assertStartAllowed();
  }

  private async fenceTeardown() {
    this.teardown = true;
    await this.ctx.storage.put(teardownKey, true);
  }

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
    this.assertStartAllowed();
    return this.trace("process-start", async () => {
      this.assertStartAllowed();
      const diagnosticRunId = env?.OMG_DIAGNOSTIC_RUN_ID;
      const reportRunId =
        env?.OMG_CI_LEAF_STEP === "rust-portable-tests"
          ? env?.OMG_REPORT_RUN_ID ??
            (diagnosticRunId && runIdPattern.test(diagnosticRunId) ? diagnosticRunId : undefined)
          : undefined;
      await this.ctx.storage.put<RunnerMetadata>(metadataKey, {
        reportRunId,
        leafStep: env?.OMG_CI_LEAF_STEP,
        diagnosticRunId,
      });
      this.assertStartAllowed();
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
  override async alarm(...args: Parameters<NativeCiSandbox["alarm"]>) {
    try {
      await releaseTerminalOwner({
        readOwner: async () => (await this.ctx.storage.get<RunnerMetadata>(metadataKey))?.diagnosticRunId,
        lookup: async (owner) => {
          const instance = await this.env.CI_WORKFLOW.get(owner);
          const status = await instance.status();

          return { id: instance.id, status: status.status };
        },
        acquire: (owner) => {
          this.cleanupOwner = owner;
        },
        release: () => {
          this.cleanupOwner = undefined;
        },
        retain: async (owner) => {
          const metadata = await this.ctx.storage.get<RunnerMetadata>(metadataKey);

          if (metadata?.diagnosticRunId !== owner)
            return {
              retained: false,
              failures: [{ evidence: "runner-metadata:owner", status: "invalid-identity" as const }],
            };

          await this.fenceTeardown();

          return retainSandboxEvidence(
            metadata,
            { listFiles: (path) => super.listFiles(path) },
            async (path) => (await super.readFile(path, { encoding: "none" })).content,
            this.env.BACKUP_BUCKET,
            owner,
          );
        },
        destroy: () => this.trace("destroy", () => super.destroy()),
        delegate: () => super.alarm(...args),
        warn: (event) => console.warn(JSON.stringify({ ...event, sandboxId: this.ctx.id.toString() })),
      });
    } catch (error) {
      console.warn(
        JSON.stringify({
          event: "sandbox_cleanup_rescheduled",
          sandboxId: this.ctx.id.toString(),
          error: error instanceof Error ? error.message : String(error),
        }),
      );
      await this.ctx.storage.setAlarm(Date.now() + 60_000);
    }
  }
  override destroy() {
    this.teardown = true;
    return this.trace("destroy", async () => {
      try {
        await this.ctx.storage.put(teardownKey, true);
        const metadata = await this.ctx.storage.get<RunnerMetadata>(metadataKey);
        const streams: { stream: string; status: string }[] = [];
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
            streams.push({ stream, status });
            if (status !== "saved")
              console.warn(JSON.stringify({ event: "runner_log_unavailable", stream, status }));
          }
        }
        try {
          await this.env.BACKUP_BUCKET.put(
            `diagnostics/sandboxes/${this.ctx.id.toString()}-retention.json`,
            JSON.stringify({
              metadataPresent: Boolean(metadata),
              runIdentityPresent: Boolean(metadata?.diagnosticRunId),
              leafIdentityPresent: Boolean(metadata?.leafStep),
              streams,
            }),
            { httpMetadata: { contentType: "application/json" } },
          );
        } catch {
          console.warn(JSON.stringify({ event: "runner_retention_diagnostic_unavailable" }));
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
