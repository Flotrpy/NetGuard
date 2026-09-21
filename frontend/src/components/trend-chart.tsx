"use client";

import { useState } from "react";
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { Dashboard } from "@/lib/types";

type Point = Dashboard["trend"][number];

function shortDate(iso: string): string {
  const d = new Date(iso + "T00:00:00Z");
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric", timeZone: "UTC" });
}

function TrendTooltip({ active, payload }: { active?: boolean; payload?: { payload: Point }[] }) {
  if (!active || !payload?.length) return null;
  const p = payload[0].payload;
  return (
    <div className="rounded-md border border-border bg-surface px-3 py-2 text-xs shadow-lg">
      <p className="mb-1 font-medium">{shortDate(p.date)}</p>
      <p>
        Active: <span className="font-semibold tabular-nums">{p.active}</span>
      </p>
      <p className="text-muted">
        Opened {p.opened} · Resolved {p.resolved}
      </p>
    </div>
  );
}

/**
 * Single-series trend of active findings. One series, so no legend box: the card title names it.
 * A table view is available for screen-reader / precise-value use.
 */
export function TrendChart({ data }: { data: Point[] }) {
  const [table, setTable] = useState(false);
  const hasData = data.some((p) => p.active > 0 || p.opened > 0 || p.resolved > 0);
  if (!hasData) {
    return <p className="py-8 text-center text-sm text-muted">No findings recorded in the last 30 days.</p>;
  }
  return (
    <div>
      <div className="mb-2 flex justify-end">
        <button className="text-xs text-accent hover:underline" onClick={() => setTable((t) => !t)}>
          {table ? "View as chart" : "View as table"}
        </button>
      </div>
      {table ? (
        <div className="max-h-64 overflow-auto">
          <table className="w-full text-sm">
            <thead>
              <tr>
                <th className="th">Date</th>
                <th className="th text-right">Active</th>
                <th className="th text-right">Opened</th>
                <th className="th text-right">Resolved</th>
              </tr>
            </thead>
            <tbody>
              {data.map((p) => (
                <tr key={p.date} className="border-t border-border">
                  <td className="td">{shortDate(p.date)}</td>
                  <td className="td text-right tabular-nums">{p.active}</td>
                  <td className="td text-right tabular-nums">{p.opened}</td>
                  <td className="td text-right tabular-nums">{p.resolved}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="h-56" role="img" aria-label="Active findings over the last 30 days">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -16 }}>
              <CartesianGrid stroke="rgb(var(--border))" strokeOpacity={0.5} vertical={false} />
              <XAxis
                dataKey="date"
                tickFormatter={shortDate}
                tick={{ fill: "rgb(var(--muted))", fontSize: 11 }}
                tickLine={false}
                axisLine={false}
                minTickGap={32}
              />
              <YAxis
                allowDecimals={false}
                tick={{ fill: "rgb(var(--muted))", fontSize: 11 }}
                tickLine={false}
                axisLine={false}
              />
              <Tooltip content={<TrendTooltip />} cursor={{ stroke: "rgb(var(--muted))", strokeOpacity: 0.4 }} />
              <Line
                type="monotone"
                dataKey="active"
                stroke="rgb(var(--accent))"
                strokeWidth={2}
                dot={false}
                activeDot={{ r: 4, stroke: "rgb(var(--surface))", strokeWidth: 2 }}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}
