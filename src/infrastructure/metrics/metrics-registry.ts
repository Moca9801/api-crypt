/**
 * Registro de métricas compatible con el formato de texto de Prometheus (v0.0.4).
 * Implementado sin dependencias externas — solo TypeScript nativo.
 *
 * Soporta:
 *  - Counters (valores acumulativos que solo aumentan)
 *  - Gauges (valores instantáneos que suben y bajan)
 *  - Histograms (distribuciones de latencia con buckets configurables)
 */

export type Labels = Record<string, string>;

interface CounterEntry { value: number; help: string; type: 'counter' | 'gauge'; }
interface HistogramEntry {
    buckets: number[];          // límites superiores de cada bucket (le=X)
    counts: number[];           // conteo de observaciones en cada bucket
    sum: number;
    count: number;
    help: string;
}

export class MetricsRegistry {
    private counters = new Map<string, Map<string, CounterEntry>>();
    private histograms = new Map<string, Map<string, HistogramEntry>>();

    // ── Counters / Gauges ────────────────────────────────────────────────────

    private counterKey(labels: Labels): string {
        return Object.entries(labels).sort(([a], [b]) => a.localeCompare(b))
            .map(([k, v]) => `${k}="${v}"`).join(',');
    }

    private labelsStr(labels: Labels): string {
        const s = this.counterKey(labels);
        return s ? `{${s}}` : '';
    }

    increment(name: string, labels: Labels = {}, help = '', amount = 1): void {
        if (!this.counters.has(name)) this.counters.set(name, new Map());
        const key = this.counterKey(labels);
        const map = this.counters.get(name)!;
        const existing = map.get(key);
        if (existing) {
            existing.value += amount;
        } else {
            map.set(key, { value: amount, help, type: 'counter' });
        }
    }

    setGauge(name: string, value: number, labels: Labels = {}, help = ''): void {
        if (!this.counters.has(name)) this.counters.set(name, new Map());
        const key = this.counterKey(labels);
        this.counters.get(name)!.set(key, { value, help, type: 'gauge' });
    }

    // ── Histograms ───────────────────────────────────────────────────────────

    observe(
        name: string,
        value: number,
        labels: Labels = {},
        help = '',
        buckets = [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000]
    ): void {
        if (!this.histograms.has(name)) this.histograms.set(name, new Map());
        const key = this.counterKey(labels);
        const map = this.histograms.get(name)!;
        if (!map.has(key)) {
            map.set(key, { buckets, counts: new Array(buckets.length).fill(0), sum: 0, count: 0, help });
        }
        const h = map.get(key)!;
        h.sum += value;
        h.count += 1;
        for (let i = 0; i < h.buckets.length; i++) {
            if (value <= h.buckets[i]) h.counts[i]++;
        }
    }

    // ── Prometheus Text Format ───────────────────────────────────────────────

    toPrometheusText(): string {
        const lines: string[] = [];

        for (const [name, labelMap] of this.counters) {
            const firstEntry = labelMap.values().next().value;
            if (!firstEntry) continue;
            lines.push(`# HELP ${name} ${firstEntry.help || name}`);
            lines.push(`# TYPE ${name} ${firstEntry.type}`);
            for (const [key, entry] of labelMap) {
                const lbl = key ? `{${key}}` : '';
                lines.push(`${name}${lbl} ${entry.value}`);
            }
        }

        for (const [name, labelMap] of this.histograms) {
            const firstEntry = labelMap.values().next().value;
            if (!firstEntry) continue;
            lines.push(`# HELP ${name} ${firstEntry.help || name}`);
            lines.push(`# TYPE ${name} histogram`);
            for (const [key, h] of labelMap) {
                const baseLabels = key ? `${key},` : '';
                // Cumulative counts per bucket
                let cumulative = 0;
                for (let i = 0; i < h.buckets.length; i++) {
                    cumulative += h.counts[i];
                    lines.push(`${name}_bucket{${baseLabels}le="${h.buckets[i]}"} ${cumulative}`);
                }
                lines.push(`${name}_bucket{${baseLabels}le="+Inf"} ${h.count}`);
                lines.push(`${name}_sum${key ? `{${key}}` : ''} ${h.sum}`);
                lines.push(`${name}_count${key ? `{${key}}` : ''} ${h.count}`);
            }
        }

        return lines.join('\n') + '\n';
    }
}

/** Instancia singleton global del registro de métricas. */
export const metricsRegistry = new MetricsRegistry();
