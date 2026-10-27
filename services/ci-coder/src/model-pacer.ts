import { DurableObject } from "cloudflare:workers";
import { PACING_INTERVAL_MS, PACING_MODEL, type Admission } from "../../ci-inspector/src/model-admission";

export class ModelPacer extends DurableObject {
  async admit(model: string): Promise<Admission> {
    if (model !== PACING_MODEL) throw new Error("Unsupported paced model");
    return this.ctx.storage.transaction(async storage => {
      const nextAt = await storage.get<number>("next-at");
      const now = Date.now();
      if (nextAt !== undefined && (!Number.isFinite(nextAt) || nextAt < 0))
        throw new Error("Invalid model admission state");
      if (nextAt !== undefined && now < nextAt)
        return { granted: false, waitMs: Math.min(PACING_INTERVAL_MS, nextAt - now) };
      await storage.put("next-at", now + PACING_INTERVAL_MS);
      return { granted: true };
    });
  }
}
