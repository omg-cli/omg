import { test, expect } from "bun:test";
import { diagnosticsHttp } from "../src/diagnostics-http";

type ListOptions = { prefix: string; limit: number; cursor?: string };

const id = "a".repeat(64);

const record = {
  version: 1,
  sandboxId: id,
  events: [
    {
      sequence: 1,
      phase: "restore",
      outcome: "failed",
      time: "2026-10-20T20:00:00.000Z",
      error: { name: "RPCTransportError", kind: "session_disposed" },
    },
  ],
  truncated: false,
};

test("owner diagnostics expose bounded FUSE exit evidence without relaxing the record schema", async () => {
  const url = new Request(`https://fixture/diagnostics/sandboxes/${id}`);
  const evidence = { ...record, fuseExitCode: 0 };

  const response = await diagnosticsHttp(url, {
    get: async () => ({ text: async () => JSON.stringify(evidence) }),
  });

  expect(response.status).toBe(200);
  expect(await response.json()).toEqual(evidence);

  const invalid = await diagnosticsHttp(url, {
    get: async () => ({ text: async () => JSON.stringify({ ...record, fuseExitCode: -1 }) }),
  });

  expect(invalid.status).toBe(503);
});

test("diagnostic reads use a fixed namespace, capped listing and explicit continuation", async () => {
  const calls: object[] = [];

  const bucket = {
    get: async () => ({ text: async () => JSON.stringify(record) }),
    list: async (options: ListOptions) => {
      calls.push(options);

      return {
        objects: [{ key: `diagnostics/sandboxes/${id}.json` }],
        truncated: true,
        cursor: "next-page",
      };
    },
  };

  const response = await diagnosticsHttp(
    new Request("https://fixture/diagnostics/sandboxes?cursor=first-page"),
    bucket,
  );

  expect(response.status).toBe(200);
  expect(calls).toEqual([{ prefix: "diagnostics/sandboxes/", limit: 50, cursor: "first-page" }]);
  expect(await response.json()).toEqual({ ids: [id], truncated: true, cursor: "next-page" });
  expect(
    (
      await diagnosticsHttp(new Request(`https://fixture/diagnostics/sandboxes/${id}`), bucket)
    ).headers.get("Cache-Control"),
  ).toBe("no-store");
});

test("diagnostic retrieval rejects arbitrary keys and raw or oversized records", async () => {
  const bucket = {
    get: async () => ({
      text: async () => JSON.stringify({ ...record, headers: "private fixture" }),
    }),
  };

  expect(
    (await diagnosticsHttp(new Request(`https://fixture/diagnostics/sandboxes/${id}`), bucket))
      .status,
  ).toBe(503);
  expect(
    (await diagnosticsHttp(new Request("https://fixture/diagnostics/sandboxes/secret"), bucket))
      .status,
  ).toBe(404);
  expect(
    (
      await diagnosticsHttp(
        new Request("https://fixture/diagnostics/sandboxes?prefix=secrets"),
        bucket,
      )
    ).status,
  ).toBe(400);

  const huge = {
    get: async () => ({
      size: 40000,
      text: async () => {
        throw new Error("must not read oversized body");
      },
    }),
  };

  expect(
    (await diagnosticsHttp(new Request(`https://fixture/diagnostics/sandboxes/${id}`), huge))
      .status,
  ).toBe(503);
});

test("diagnostic listing skips only retention sidecars and keeps bounded continuation", async () => {
  const calls: ListOptions[] = [];
  const reads: string[] = [];
  const sidecarId = "b".repeat(64);

  const bucket = {
    get: async (key: string) => {
      reads.push(key);
      return null;
    },
    list: async (options: ListOptions) => {
      calls.push(options);

      return {
        objects: [
          { key: `diagnostics/sandboxes/${id}.json` },
          { key: `diagnostics/sandboxes/${sidecarId}-retention.json` },
        ],
        truncated: true,
        cursor: "next-page",
      };
    },
  };

  const response = await diagnosticsHttp(
    new Request("https://fixture/diagnostics/sandboxes?cursor=first-page"),
    bucket,
  );

  expect(response.status).toBe(200);
  expect(calls).toEqual([{ prefix: "diagnostics/sandboxes/", limit: 50, cursor: "first-page" }]);
  expect(await response.json()).toEqual({ ids: [id], truncated: true, cursor: "next-page" });
  expect(reads).toEqual([]);
});

test("diagnostic listing rejects unknown malformed keys next to retention sidecars", async () => {
  const bucket = {
    get: async () => null,
    list: async () => ({
      objects: [
        { key: `diagnostics/sandboxes/${id}.json` },
        { key: `diagnostics/sandboxes/${id}-retention.json` },
        { key: `diagnostics/sandboxes/${id}-retention.txt` },
      ],
      truncated: false,
    }),
  };

  const response = await diagnosticsHttp(
    new Request("https://fixture/diagnostics/sandboxes"),
    bucket,
  );

  expect(response.status).toBe(503);
  expect(await response.json()).toEqual({ error: "Diagnostics unavailable" });
});

test("diagnostic listing rejects a retention suffix that is not bound to a sandbox id", async () => {
  const bucket = {
    get: async () => null,
    list: async () => ({
      objects: [{ key: "diagnostics/sandboxes/not-a-sandbox-retention.json" }],
      truncated: false,
    }),
  };

  expect(
    (await diagnosticsHttp(new Request("https://fixture/diagnostics/sandboxes"), bucket)).status,
  ).toBe(503);
});
