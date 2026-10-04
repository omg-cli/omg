import { createHash } from 'node:crypto';

// Paperclip 2026.1001.0, build 8f8a0ab7effbd6a0584107d8038736c134ee5047.
// This transformer stages a candidate; importing it never mutates the runtime.
export const expectedServiceSha256 = '99ad0be24af09f1b5e214db4fb7435766b6f9095c9085a4347e83a18d6e86c86';

export function patchCrossIssueAttribution(source) {
  const digest = createHash('sha256').update(source).digest('hex');
  if (digest !== expectedServiceSha256) {
    throw new Error(`Unsupported cross-issue service SHA-256: ${digest}; inspect the new source before applying compatibility`);
  }
  const original = '        const sourceIssueId = readRunSourceIssueId(run.contextSnapshot);';
  const replacement = `        // A timer run has no task snapshot even after a sanctioned checkout.
        // Use only its first server-authored checkout audit record as fallback.
        // The validated run row remains locked, and the counter stays run-scoped.
        const checkout = readRunSourceIssueId(run.contextSnapshot) ? null : await tx
            .select({ issueId: activityLog.entityId })
            .from(activityLog)
            .where(and(eq(activityLog.companyId, input.companyId),
                eq(activityLog.runId, input.runId), eq(activityLog.agentId, input.agentId),
                eq(activityLog.actorType, "agent"), eq(activityLog.actorId, input.agentId),
                eq(activityLog.action, "issue.checked_out"), eq(activityLog.entityType, "issue")))
            .orderBy(asc(activityLog.createdAt), asc(activityLog.id))
            .limit(1)
            .then((rows) => rows[0] ?? null);
        const sourceIssueId = readRunSourceIssueId(run.contextSnapshot) ??
            (isUuidLike(checkout?.issueId) ? checkout.issueId : null);`;
  if (source.split(original).length !== 2) throw new Error('Ambiguous source attribution anchor');
  return source.replace('import { and, count, eq }', 'import { and, asc, count, eq }')
    .replace(original, replacement);
}
