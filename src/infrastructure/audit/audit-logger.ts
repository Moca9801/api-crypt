/**
 * Audit logger — emite eventos criptográficos críticos a stdout en formato JSON.
 *
 * Diseñado para ser compatible con cualquier aggregador de logs:
 * ELK Stack, Grafana Loki, Datadog, AWS CloudWatch, etc.
 *
 * Formato: una línea JSON por evento con timestamp ISO 8601 y level=AUDIT.
 */

export type AuditEvent =
    | { event: 'key.created';       keyId: string; type: string; ip: string }
    | { event: 'key.rotated';       keyId: string; ip: string }
    | { event: 'key.disabled';      keyId: string; ip: string }
    | { event: 'key.policy.set';    keyId: string; ttlDays: number; ip: string }
    | { event: 'managed.encrypt';   keyId: string; ip: string }
    | { event: 'managed.decrypt';   keyId: string; ip: string }
    | { event: 'managed.sign';      keyId: string; ip: string }
    | { event: 'key.rotated.auto';  keyId: string }
    | { event: 'auth.failure';      ip: string; reason: 'missing_key' | 'invalid_key' };

export function auditLog(e: AuditEvent): void {
    const entry = { ...e, ts: new Date().toISOString(), level: 'AUDIT' };
    // process.stdout.write es sync y thread-safe en Node.js — ideal para audit logs
    process.stdout.write(JSON.stringify(entry) + '\n');
}
