type Ai = import("@cloudflare/workers-types/index.ts").Ai;

type WorkerLoader = import("@cloudflare/workers-types/index.ts").WorkerLoader;

type Fetcher = import("@cloudflare/workers-types/index.ts").Fetcher;

type DurableObjectState = import("@cloudflare/workers-types/index.ts").DurableObjectState;

type ExecutionContext = import("@cloudflare/workers-types/index.ts").ExecutionContext;

type GatewayOptions = import("@cloudflare/workers-types/index.ts").GatewayOptions;

type AiModels = import("@cloudflare/workers-types/index.ts").AiModels;

type BaseAiTextGeneration = import("@cloudflare/workers-types/index.ts").BaseAiTextGeneration;

type BaseAiTextToImage = import("@cloudflare/workers-types/index.ts").BaseAiTextToImage;

type BaseAiTextEmbeddings = import("@cloudflare/workers-types/index.ts").BaseAiTextEmbeddings;

type BaseAiAutomaticSpeechRecognition =
  import("@cloudflare/workers-types/index.ts").BaseAiAutomaticSpeechRecognition;

type BaseAiTextToSpeech = import("@cloudflare/workers-types/index.ts").BaseAiTextToSpeech;

type AutoRAG = import("@cloudflare/workers-types/index.ts").AutoRAG;

declare module "cloudflare:workers" {
  export import WorkerEntrypoint = CloudflareWorkersModule.WorkerEntrypoint;
  export import DurableObject = CloudflareWorkersModule.DurableObject;
  export import RpcTarget = CloudflareWorkersModule.RpcTarget;
  import { CloudflareWorkersModule } from "@cloudflare/workers-types/index.ts";
}
