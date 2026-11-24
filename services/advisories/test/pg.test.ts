import { describe, expect, test } from "bun:test";
import { translateSqlForPostgres } from "../src/pg";

describe("translateSqlForPostgres", () => {
    test("rewrites ? placeholders while preserving string literals", () => {
        const sql = "SELECT * FROM source_record WHERE id=? AND source_url LIKE 'https://example.com/?a=1' AND supported=?";
        expect(translateSqlForPostgres(sql)).toBe(
            "SELECT * FROM source_record WHERE id=$1 AND source_url LIKE 'https://example.com/?a=1' AND supported=$2",
        );
    });

    test("translates mutation_fence strftime UTC timestamp", () => {
        const sql =
            "INSERT INTO mutation_fence(id,valid) VALUES(1,CASE WHEN EXISTS(SELECT 1 FROM ingestion_lease WHERE source=? AND owner=? AND expires_at>COALESCE(?,strftime('%Y-%m-%dT%H:%M:%fZ','now'))) THEN 1 ELSE 0 END) ON CONFLICT(id) DO UPDATE SET valid=excluded.valid";
        const pg = translateSqlForPostgres(sql);
        expect(pg).toContain("source=$1 AND owner=$2 AND expires_at>COALESCE($3,to_char(clock_timestamp() AT TIME ZONE 'UTC'");
        expect(pg).not.toContain("strftime");
    });

    test("translates aliased json_each and json_extract in baseline conflict check", () => {
        const sql =
            "SELECT b.cve_id FROM json_each(?) j CROSS JOIN baseline_member b ON b.session_id=? AND b.cve_id=json_extract(j.value,'$.id') WHERE b.payload_sha256<>json_extract(j.value,'$.hash') LIMIT 1";
        expect(translateSqlForPostgres(sql)).toBe(
            "SELECT b.cve_id FROM jsonb_array_elements($1::jsonb) AS j(value) CROSS JOIN baseline_member b ON b.session_id=$2 AND b.cve_id=(j.value->>'id') WHERE b.payload_sha256<>(j.value->>'hash') LIMIT 1",
        );
    });

    test("translates unaliased json_each with WHERE 1 ON CONFLICT", () => {
        const sql =
            "INSERT INTO baseline_member(session_id,cve_id,payload_sha256) SELECT ?,json_extract(value,'$.id'),json_extract(value,'$.hash') FROM json_each(?) WHERE 1 ON CONFLICT(session_id,cve_id) DO NOTHING";
        expect(translateSqlForPostgres(sql)).toBe(
            "INSERT INTO baseline_member(session_id,cve_id,payload_sha256) SELECT $1,(_je.value->>'id'),(_je.value->>'hash') FROM jsonb_array_elements($2::jsonb) AS _je(value) WHERE true ON CONFLICT(session_id,cve_id) DO NOTHING",
        );
    });

    test("translates kev_annotation bulk insert", () => {
        const sql =
            "INSERT INTO kev_annotation(cve_id,payload_json,catalog_sha256) SELECT json_extract(value,'$.cveID'),value,? FROM json_each(?)";
        expect(translateSqlForPostgres(sql)).toBe(
            "INSERT INTO kev_annotation(cve_id,payload_json,catalog_sha256) SELECT (_je.value->>'cveID'),_je.value::text,$1 FROM jsonb_array_elements($2::jsonb) AS _je(value)",
        );
    });
});
