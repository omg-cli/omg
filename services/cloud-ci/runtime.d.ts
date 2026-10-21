type Artifacts = import("@cloudflare/workers-types/index.ts").Artifacts;

type R2Bucket = import("@cloudflare/workers-types/index.ts").R2Bucket;

type DurableObjectNamespace<
  T extends import("@cloudflare/workers-types/index.ts").Rpc.DurableObjectBranded | undefined =
    undefined,
> = import("@cloudflare/workers-types/index.ts").DurableObjectNamespace<T>;

type DurableObjectState<Props = unknown> =
  import("@cloudflare/workers-types/index.ts").DurableObjectState<Props>;

type DurableObjectStorage = import("@cloudflare/workers-types/index.ts").DurableObjectStorage;

type ExecutionContext = import("@cloudflare/workers-types/index.ts").ExecutionContext;

type Fetcher = import("@cloudflare/workers-types/index.ts").Fetcher;

type Workflow<T = unknown> = import("@cloudflare/workers-types/index.ts").Workflow<T>;

declare namespace Cloudflare {
  type Env = import("./src/env").Env;
}

declare module "cloudflare:workers" {
  export import WorkerEntrypoint = CloudflareWorkersModule.WorkerEntrypoint;
  export import DurableObject = CloudflareWorkersModule.DurableObject;
  export import RpcTarget = CloudflareWorkersModule.RpcTarget;
  export import WorkflowEntrypoint = CloudflareWorkersModule.WorkflowEntrypoint;
  export import WorkflowEvent = CloudflareWorkersModule.WorkflowEvent;
  export import WorkflowStep = CloudflareWorkersModule.WorkflowStep;
  import { CloudflareWorkersModule } from "@cloudflare/workers-types/index.ts";
}

type AlarmInvocationInfo = import("@cloudflare/workers-types/index.ts").AlarmInvocationInfo;

type DurableObjectStub<
  T extends import("@cloudflare/workers-types/index.ts").Rpc.DurableObjectBranded | undefined =
    undefined,
> = import("@cloudflare/workers-types/index.ts").DurableObjectStub<T>;

type R2PutOptions = import("@cloudflare/workers-types/index.ts").R2PutOptions;

type ExportedHandler<Environment = unknown> =
  import("@cloudflare/workers-types/index.ts").ExportedHandler<Environment>;
