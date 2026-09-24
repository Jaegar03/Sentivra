"use client";

import { Bar, BarChart, CartesianGrid, LabelList, Tooltip, XAxis, YAxis, type TooltipContentProps } from "recharts";

import { SeverityBadge } from "@/components/sentivra/badges";
import { integer } from "@/lib/format";
import { SEVERITIES, type Severity } from "@/types/api";

// Mark specs from the data-viz guide: bars <= 24px thick with a 4px rounded
// data end and a square baseline; hairline, solid, recessive grid and axes;
// text in ink tokens, never in the series color. One series, one color
// (slot 1): these are nominal categories, so no value ramp.
const TICK = { fill: "var(--ink-muted)", fontSize: 12 };
const BAR_THICKNESS = 14;

function ValueTooltip({ active, payload, label }: TooltipContentProps) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-md border bg-popover px-3 py-2 text-xs shadow-sm">
      <div className="text-sm font-semibold tabular text-foreground">{integer(Number(payload[0].value))}</div>
      <div className="text-muted-foreground">{label}</div>
    </div>
  );
}

/** Horizontal bars for a nominal breakdown (detector, category), sorted by value. */
export function CategoryBars({ data, labelWidth = 170 }: { data: { label: string; value: number }[]; labelWidth?: number }) {
  const height = Math.max(96, data.length * 34 + 28);
  return (
    <BarChart
      responsive
      style={{ width: "100%", height }}
      data={data}
      layout="vertical"
      margin={{ top: 4, right: 40, bottom: 4, left: 0 }}
      accessibilityLayer
    >
      <CartesianGrid horizontal={false} stroke="var(--grid)" strokeWidth={1} />
      <XAxis type="number" allowDecimals={false} tick={TICK} stroke="var(--axis)" tickLine={false} />
      <YAxis type="category" dataKey="label" width={labelWidth} tick={TICK} stroke="var(--axis)" tickLine={false} interval={0} />
      <Tooltip content={ValueTooltip} cursor={{ fill: "var(--muted)", opacity: 0.6 }} />
      <Bar dataKey="value" fill="var(--series-1)" barSize={BAR_THICKNESS} radius={[0, 4, 4, 0]} isAnimationActive={false}>
        <LabelList dataKey="value" position="right" style={{ fill: "var(--foreground)", fontSize: 12 }} />
      </Bar>
    </BarChart>
  );
}

/** Alerts per time bucket: one series, columns, value in the tooltip and table. */
export function TimelineColumns({ data }: { data: { label: string; value: number }[] }) {
  return (
    <BarChart
      responsive
      style={{ width: "100%", height: 220 }}
      data={data}
      margin={{ top: 8, right: 8, bottom: 0, left: -12 }}
      accessibilityLayer
    >
      <CartesianGrid vertical={false} stroke="var(--grid)" strokeWidth={1} />
      <XAxis dataKey="label" tick={TICK} stroke="var(--axis)" tickLine={false} interval="preserveStartEnd" minTickGap={24} />
      <YAxis allowDecimals={false} tick={TICK} stroke="var(--axis)" tickLine={false} width={40} />
      <Tooltip content={ValueTooltip} cursor={{ fill: "var(--muted)", opacity: 0.6 }} />
      <Bar dataKey="value" fill="var(--series-1)" maxBarSize={24} radius={[4, 4, 0, 0]} isAnimationActive={false} />
    </BarChart>
  );
}

/**
 * Severity distribution as an HTML bar list. The bars are one color (slot 1);
 * severity is carried by the badge on each row (status color + icon + word),
 * because MEDIUM and HIGH aren't separable by status hue alone.
 */
export function SeverityBars({ counts }: { counts: Record<Severity, number> }) {
  // Alerts are never SAFE (SAFE results don't raise one), so that row would only ever read 0.
  const order = SEVERITIES.filter((s) => s !== "SAFE").reverse();
  const max = Math.max(1, ...order.map((s) => counts[s] ?? 0));
  return (
    <ul className="space-y-2.5">
      {order.map((s) => {
        const value = counts[s] ?? 0;
        return (
          <li key={s} className="grid grid-cols-[6.5rem_1fr_3rem] items-center gap-3" title={`${s}: ${value}`}>
            <SeverityBadge severity={s} className="justify-self-start" />
            <div className="h-3.5 rounded-r-[4px]" style={{ width: `${(value / max) * 100}%`, minWidth: value ? 4 : 0, background: "var(--series-1)" }} />
            <span className="text-right text-sm tabular">{integer(value)}</span>
          </li>
        );
      })}
    </ul>
  );
}
