import { readFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import { boundedBody, object } from "../advisories/src/domain";
import { STAGE_MODE } from "./stage-identity";

const ACCOUNT = "f1e95b3e1b502cf366dfc81a863695fa";
const STAGE = "omg-advisories-stage-20261121-1d6c61c4";
const INCUMBENT = "omg-advisories";
const INCUMBENT_D1 = "98202f8c-7d5f-4de9-8ddd-cea35fd95d09";
const INCUMBENT_R2 = "omg-advisories-raw";
const HOST = "https://api.cloudflare.com";
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;

function require(condition: unknown, message: string): asserts condition {
    if (!condition) throw new Error(message);
}

function array(value: unknown) {
    require(Array.isArray(value) && value.length <= 256, "invalid bounded provider list");
    return value.map(object);
}

function exactOne(values: unknown) {
    const entries = array(values);
    require(entries.length === 1 && entries[0], "expected exactly one binding or active version");
    return entries[0];
}

function named(entries: ReturnType<typeof array>, name: string) {
    return exactOne(entries.filter(entry => entry.name === name));
}

function bindings(version: Record<string, unknown>) {
    return array(object(version.resources).bindings);
}

function physical(entries: ReturnType<typeof bindings>) {
    const d1 = named(entries, "DB"), r2 = named(entries, "RAW");
    require(d1.type === "d1" && typeof d1.id === "string" && UUID.test(d1.id), "missing effective physical D1 ID");
    require(r2.type === "r2_bucket" && typeof r2.bucket_name === "string" &&
        (r2.jurisdiction === undefined || r2.jurisdiction === "default"), "missing or non-default effective R2 identity");
    return { d1: d1.id, r2: r2.bucket_name };
}

function active(deployments: Record<string, unknown>) {
    const latest = array(deployments.deployments)[0];
    require(latest, "no effective live deployment to compare");
    const serving = exactOne(latest.versions);
    require(serving.percentage === 100 && typeof serving.version_id === "string" && UUID.test(serving.version_id), "ambiguous active deployment");
    return serving.version_id;
}

type ApiFetcher = (url: string, init: RequestInit) => Promise<Response>;

export async function admit(approved: Record<string, unknown>, config: Record<string, unknown>,
    candidate: string, credential: string, fetcher: ApiFetcher = fetch) {
    const d1 = approved.d1_id, r2 = approved.r2_bucket;
    require(approved.account_id === ACCOUNT && approved.worker === STAGE &&
        typeof d1 === "string" && UUID.test(d1) && d1 !== INCUMBENT_D1 &&
        d1 !== "00000000-0000-0000-0000-000000000000" &&
        r2 !== INCUMBENT_R2 && r2 === `${STAGE}-raw` && approved.r2_jurisdiction === "default", "unapproved physical stage identities");
    require(UUID.test(candidate) && credential.length > 0, "exact candidate version and read-only API authorization required");
    require(config.account_id === ACCOUNT && config.name === STAGE && config.main === "stage.ts" &&
        config.workers_dev === false && config.preview_urls === false &&
        !("route" in config || "routes" in config || "env" in config || "triggers" in config), "intended stage routing must be disabled");
    const intendedD1 = exactOne(config.d1_databases), intendedR2 = exactOne(config.r2_buckets), vars = object(config.vars);
    require(intendedD1.binding === "DB" && intendedD1.database_id === d1 && intendedD1.database_name === STAGE &&
        intendedR2.binding === "RAW" && intendedR2.bucket_name === r2 &&
        (intendedR2.jurisdiction === undefined || intendedR2.jurisdiction === "default"), "intended physical stage bindings differ");
    require(vars.STAGE_MODE === STAGE_MODE && vars.STAGE_ENABLE_CRON === "false" &&
        typeof vars.STAGE_ACCESS_AUD === "string" && /^[a-f0-9]{64}$/.test(vars.STAGE_ACCESS_AUD) &&
        typeof vars.STAGE_DATABASE_INSTANCE_ID === "string" && /^[a-f0-9]{32}$/.test(vars.STAGE_DATABASE_INSTANCE_ID), "intended draft policy is incomplete");

    async function get(path: string) {
        const url = `${HOST}/client/v4/accounts/${ACCOUNT}/${path}`;
        const res = await fetcher(url, { redirect: "error", signal: AbortSignal.timeout(15_000),
            headers: { authorization: `Bearer ${credential}`, "cf-r2-jurisdiction": "default" } });
        require(res.ok && !res.redirected && (!res.url || res.url === url), "Cloudflare read-only evidence unavailable");
        const envelope = object(JSON.parse(await boundedBody(res.body, 1024 * 1024)));
        require(envelope.success === true, "Cloudflare rejected read-only evidence");
        return object(envelope.result);
    }

    const stageScript = `workers/scripts/${STAGE}`, prodScript = `workers/scripts/${INCUMBENT}`;
    const [route, stageDeployments, prodDeployments, database, bucket, draft] = await Promise.all([
        get(`${stageScript}/subdomain`), get(`${stageScript}/deployments`), get(`${prodScript}/deployments`),
        get(`d1/database/${d1}`), get(`r2/buckets/${r2}`), get(`${stageScript}/versions/${candidate}`),
    ]);
    require(route.enabled === false && route.previews_enabled === false, "stage routes or previews are already enabled");
    const oldStage = active(stageDeployments), oldProd = active(prodDeployments);
    require(oldStage !== candidate, "candidate is already active");
    const [stub, prod] = await Promise.all([get(`${stageScript}/versions/${oldStage}`), get(`${prodScript}/versions/${oldProd}`)]);
    require(stub.id === oldStage && prod.id === oldProd && draft.id === candidate, "effective version identity differs");
    const inert = bindings(stub);
    const stubMode = named(inert, "STAGE_MODE");
    require(stubMode.type === "plain_text" && stubMode.text === "disabled" &&
        !inert.some(entry => entry.type === "d1" || entry.type === "r2_bucket"),
        "active staging stub is not inert");
    const actual = bindings(draft), candidateStores = physical(actual), prodStores = physical(bindings(prod));
    require(actual.filter(entry => entry.type === "d1" || entry.type === "r2_bucket").length === 2 &&
        candidateStores.d1 === d1 && candidateStores.r2 === r2 &&
        candidateStores.d1 !== prodStores.d1 && candidateStores.r2 !== prodStores.r2, "effective stage stores are unknown or overlap the incumbent");
    require(database.uuid === d1 && database.name === STAGE &&
        bucket.name === r2 && bucket.jurisdiction === "default" && bucket.storage_class === "Standard", "physical resource descriptions differ");
    for (const name of ["STAGE_MODE", "STAGE_ENABLE_CRON", "STAGE_ACCESS_AUD", "STAGE_DATABASE_INSTANCE_ID"]) {
        const entry = named(actual, name);
        require(entry.type === "plain_text" && entry.text === vars[name], "effective draft policy differs");
    }
    return { phase: "admitted_off_traffic", version: candidate, stage_d1_id: d1, stage_r2_bucket: r2, incumbent_version: oldProd };
}

if (import.meta.main) {
    try {
        const { values } = parseArgs({ strict: true, options: { approved: { type: "string" }, config: { type: "string" }, version: { type: "string" } } });
        require(values.approved && values.config && values.version, "approved manifest, fixed stage config and exact draft version required");
        const json = async (path: string) => object(JSON.parse(await readFile(path, "utf8")));
        const [approved, config] = await Promise.all([json(values.approved), json(values.config)]);
        console.log(JSON.stringify(await admit(approved, config, values.version, process.env.CLOUDFLARE_API_TOKEN ?? "")));
    } catch {
        console.error("Stage admission refused; do not enable routes or deploy the draft");
        process.exitCode = 1;
    }
}
