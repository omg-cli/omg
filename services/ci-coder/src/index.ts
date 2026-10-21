import type { Env } from "./env.js";
import { handleCoderRequest } from "./request.js";
import { createRequiredSkillsPlugin } from "./skills.js";

export { Coder } from "./harness.js";

export default {
  fetch(request: Request, env: Env) {
    return handleCoderRequest(request, env, async () => {
      await createRequiredSkillsPlugin();
    });
  },
};
