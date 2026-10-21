import { expect, test } from "bun:test";
import { retryDecision } from "../src/runtime";

const rateLimited = {
  type: "ai_error",
  message: "AiError: rate limiting: inference request per min rate reached",
};

test("a per-minute rate rejection waits one bounded minute within the existing ceiling", () => {
  expect(retryDecision({ attempt: 1, error: rateLimited })).toEqual({ retry: true, delay: 60000 });
  expect(retryDecision({ attempt: 1, error: { ...rateLimited, status: 429 } })).toEqual({
    retry: true,
    delay: 60000,
  });
  expect(retryDecision({ attempt: 2, error: rateLimited })).toEqual({ retry: false });
  expect(retryDecision({ attempt: 3, error: { ...rateLimited, status: 429 } })).toEqual({ retry: false });
});

test("an explicit authorization or validation failure is never converted into a retry", () => {
  expect(
    retryDecision({
      attempt: 1,
      error: {
        type: "invalid",
        status: 401,
        message: "rate limit settings are unavailable to this credential",
      },
    }),
  ).toBeNull();
  expect(
    retryDecision({ attempt: 1, error: { type: "invalid", status: 400, message: "invalid request" } }),
  ).toBeNull();
});

test("an unrelated failure keeps the SDK default decision", () => {
  expect(
    retryDecision({ attempt: 1, error: { type: "server", status: 500, message: "internal error" } }),
  ).toBeNull();
});
