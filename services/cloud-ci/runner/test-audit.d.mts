import type { TestAudit } from "../src/test-audit-contract";

export type TestAuditPhase = "oldIntact" | "oldFault" | "strongerFault" | "strongerIntact";
export const testAuditPhases: readonly ["oldIntact", "oldFault", "strongerFault", "strongerIntact"];
export const testAuditReportNames: readonly string[];
export function testAuditPhasesFor(proposal: TestAudit["proposal"]): readonly TestAuditPhase[];
export function auditHash(value: string | Uint8Array): string;
export function validateTestAuditProposal<T>(proposal: T): T;
export function testAuditPhaseSource(proposal: TestAudit["proposal"], phase: TestAuditPhase): string;
type State = {
    testName: string; exitCode: number; failures: number; tests: number; errors: number; skipped: number;
    sourceSha256: string; recipeSha256: string;
    assertionFile?: string; assertionLine?: number; assertionSourceSha256?: string;
};
export function runTestAuditStates<T extends State>(proposal: TestAudit["proposal"], controller: {
    writeTest(content: string): Promise<void>;
    writeFault(active: boolean, phase?: TestAuditPhase): Promise<void>;
    verify(phase: TestAuditPhase): Promise<void>;
    run(phase: TestAuditPhase): Promise<T>;
}): Promise<{ oldIntact: T; oldFault: T; strongerFault?: T; strongerIntact?: T }>;
