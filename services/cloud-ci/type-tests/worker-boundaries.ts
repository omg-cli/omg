import type * as Workers from "@cloudflare/workers-types/index.ts";
import type { Container, ContainerProxy } from "@cloudflare/containers";
import type { Sandbox } from "@cloudflare/sandbox";
import type { CiRunnerResult } from "@cloudflare/ci";
import type { CiBindings } from "@cloudflare/ci/worker";
import type { CiSandbox } from "../src/index";

type CiRunStepOutput = Pick<CiRunnerResult, "exitCode" | "logs" | "snapshot" | "cachePointer">;

declare const request: Workers.Request;
declare const container: Container;
declare const proxy: ContainerProxy;
declare const sandbox: Sandbox;
declare const ciSandbox: CiSandbox;
declare const actualSandboxNamespace: Workers.DurableObjectNamespace<CiSandbox>;
declare const stream: Workers.ReadableStream<Uint8Array>;
declare const step: Workers.CloudflareWorkersModule.WorkflowStep;

export const containerResponse: Promise<Workers.Response> = container.fetch(request);
export const proxyResponse: Promise<Workers.Response> = proxy.fetch(request);
export const sandboxResponse: Promise<Workers.Response> = sandbox.fetch(request);
export const cancellation: Promise<void> = ciSandbox.cancel();
export const sdkSandboxNamespace: CiBindings["SANDBOX"] = actualSandboxNamespace;

export const sandboxStream: Promise<Workers.ReadableStream<Uint8Array>> =
  sandbox.readFileStream("/workspace/log.txt");

export const logs: CiRunnerResult["logs"] = { stdout: stream, stderr: "" };

export const persisted: Promise<CiRunStepOutput> = step.do(
  "actual-worker-log-contract",
  async (): Promise<CiRunStepOutput> => ({
    exitCode: 0,
    logs,
    snapshot: { id: "fixture", dir: "/workspace" },
  }),
);
