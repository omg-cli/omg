import { cloudCiChecks } from "../runner/plan.mjs";

type BackupCredentials = {
  R2_ACCESS_KEY_ID?: string;
  R2_SECRET_ACCESS_KEY?: string;
};

export function leafSnapshotOptions(step?: string) {
  if (!step || step === "frozen-dependencies" || !cloudCiChecks.includes(step)) return {};

  return { excludes: ["*", ".*"] };
}

export function backupTransferMode(environment: BackupCredentials) {
  return environment.R2_ACCESS_KEY_ID && environment.R2_SECRET_ACCESS_KEY
    ? "native-r2-auto"
    : "binding-rpc";
}
