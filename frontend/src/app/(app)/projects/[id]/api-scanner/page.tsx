"use client";

import { Globe } from "lucide-react";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useState, type FormEvent } from "react";
import { ScanProgress } from "@/components/scan-progress";
import { Card, ErrorBanner, PageHeader, Tag } from "@/components/ui";
import { api } from "@/lib/api";
import { timeAgo } from "@/lib/format";
import type { Scan } from "@/lib/types";

interface Options {
  authorization_text: string;
  public_targets_allowed: boolean;
  safe_methods_only: boolean;
  checks: string[];
  limitations: string[];
}

export default function ApiScannerPage() {
  const { id } = useParams<{ id: string }>();
  const [options, setOptions] = useState<Options | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [activeScan, setActiveScan] = useState<string | null>(null);

  const [baseUrl, setBaseUrl] = useState("");
  const [spec, setSpec] = useState("");
  const [authHeader, setAuthHeader] = useState("Authorization");
  const [authValue, setAuthValue] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [statement, setStatement] = useState("");
  const [starting, setStarting] = useState(false);

  const load = useCallback(async () => {
    try {
      const [opts, sc] = await Promise.all([
        api<Options>("/api/api-scanner/options"),
        api<Scan[]>(`/api/projects/${id}/api-scans`),
      ]);
      setOptions(opts);
      setScans(sc);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load API scanner");
    }
  }, [id]);
  useEffect(() => {
    load();
  }, [load]);

  async function startScan(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setStarting(true);
    try {
      const scan = await api<Scan>("/api/api-scans", {
        method: "POST",
        body: {
          project_id: id,
          base_url: baseUrl,
          spec: spec || undefined,
          auth_header_name: authHeader,
          auth_value: authValue || undefined,
          authorized,
          authorization_statement: statement,
        },
      });
      setActiveScan(scan.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not start scan");
    } finally {
      setStarting(false);
    }
  }

  if (!options) return error ? <ErrorBanner message={error} /> : null;

  return (
    <>
      <PageHeader title="API security scanner" subtitle="Non-destructive OpenAPI analysis and live checks" />
      <ErrorBanner message={error} />

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Run an API scan">
          <form onSubmit={startScan} className="space-y-3">
            <label className="block text-sm">
              <span className="mb-1 block text-xs text-muted">Base URL</span>
              <input
                className="input"
                required
                placeholder="https://api.example.com"
                value={baseUrl}
                onChange={(e) => setBaseUrl(e.target.value)}
              />
            </label>
            <label className="block text-sm">
              <span className="mb-1 block text-xs text-muted">OpenAPI spec (JSON or YAML, optional)</span>
              <textarea className="input font-mono text-xs" rows={5} value={spec} onChange={(e) => setSpec(e.target.value)} />
            </label>
            <div className="grid grid-cols-2 gap-3">
              <label className="text-sm">
                <span className="mb-1 block text-xs text-muted">Auth header name</span>
                <input className="input" value={authHeader} onChange={(e) => setAuthHeader(e.target.value)} />
              </label>
              <label className="text-sm">
                <span className="mb-1 block text-xs text-muted">Auth header value (optional)</span>
                <input className="input" type="password" value={authValue} onChange={(e) => setAuthValue(e.target.value)} />
              </label>
            </div>
            <div className="rounded-md border border-border bg-surface-2 p-3 text-xs text-muted">
              {options.authorization_text}
            </div>
            <label className="flex items-start gap-2 text-sm">
              <input type="checkbox" className="mt-1" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} />
              I confirm I am authorized to test this API.
            </label>
            <textarea
              className="input"
              rows={2}
              required
              minLength={20}
              value={statement}
              onChange={(e) => setStatement(e.target.value)}
              placeholder="Authorization statement (20+ characters)"
            />
            <button className="btn btn-primary" disabled={starting || !authorized}>
              <Globe className="h-4 w-4" aria-hidden /> Start scan
            </button>
          </form>
          {activeScan && (
            <div className="mt-5 border-t border-border pt-4">
              <ScanProgress scanId={activeScan} scannerNames={{ api: "API scanner" }} onFinished={load} />
            </div>
          )}
        </Card>

        <Card title="What this checks">
          <ul className="mb-4 flex flex-wrap gap-2">
            {options.checks.map((c) => (
              <Tag key={c}>{c}</Tag>
            ))}
          </ul>
          <p className="mb-2 text-sm font-medium">Limitations</p>
          <ul className="list-disc space-y-1 pl-5 text-sm text-muted">
            {options.limitations.map((l) => (
              <li key={l}>{l}</li>
            ))}
          </ul>
        </Card>
      </div>

      <Card title="Scan history" className="mt-6">
        {scans.length === 0 ? (
          <p className="text-sm text-muted">No API scans yet.</p>
        ) : (
          <ul className="divide-y divide-border">
            {scans.map((s) => (
              <li key={s.id} className="flex items-center justify-between py-2 text-sm">
                <span>
                  <span className="font-medium">{s.ref}</span>
                  <span className="block text-xs text-muted">
                    {timeAgo(s.created_at)} · {s.status}
                  </span>
                </span>
                <Tag>{s.status}</Tag>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </>
  );
}
