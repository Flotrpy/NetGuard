"use client";

import { useEffect, useRef, useState } from "react";
import { ProgressBar } from "@/components/ui";
import { api } from "@/lib/api";
import type { Scan } from "@/lib/types";

const ACTIVE = new Set(["queued", "running"]);

/**
 * Polls a scan and renders per-scanner progress. Polling runs in the background so the rest of
 * the UI stays interactive. Calls `onFinished` once when the scan reaches a terminal state.
 */
export function ScanProgress({
  scanId,
  onFinished,
  scannerNames,
}: {
  scanId: string;
  onFinished?: (scan: Scan) => void;
  scannerNames?: Record<string, string>;
}) {
  const [scan, setScan] = useState<Scan | null>(null);
  const finished = useRef(false);

  useEffect(() => {
    finished.current = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let cancelled = false;

    async function tick() {
      try {
        const s = await api<Scan>(`/api/scans/${scanId}`);
        if (cancelled) return;
        setScan(s);
        if (!ACTIVE.has(s.status)) {
          if (!finished.current) {
            finished.current = true;
            onFinished?.(s);
          }
          return;
        }
      } catch {
        /* transient error: keep polling */
      }
      timer = setTimeout(tick, 1500);
    }
    tick();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId]);

  if (!scan) return <p className="text-sm text-muted">Starting scan…</p>;
  const heading =
    scan.status === "queued"
      ? "Scan queued: waiting for a worker"
      : scan.status === "running"
        ? "Scan in progress"
        : `Scan ${scan.status}`;

  return (
    <div aria-live="polite">
      <p className="mb-3 text-sm font-medium">{heading}</p>
      <ul className="space-y-3">
        {scan.scanners.map((name) => {
          const p = scan.progress[name] ?? { state: "pending", percent: 0 };
          return (
            <li key={name}>
              <div className="mb-1 flex items-center justify-between text-xs">
                <span className="font-medium">{scannerNames?.[name] ?? name}</span>
                <span className="text-muted">
                  {p.state === "completed"
                    ? `done${p.findings !== undefined ? ` · ${p.findings} finding${p.findings === 1 ? "" : "s"}` : ""}`
                    : p.state === "failed"
                      ? "failed"
                      : `${p.percent}%`}
                </span>
              </div>
              <ProgressBar percent={p.percent} state={p.state} />
            </li>
          );
        })}
      </ul>
      {scan.error && <p className="mt-3 text-sm text-sev-critical">{scan.error}</p>}
    </div>
  );
}
