"use client";

import { Download, Radar } from "lucide-react";
import { useParams } from "next/navigation";
import { Fragment, useCallback, useEffect, useState, type FormEvent } from "react";
import { ScanProgress } from "@/components/scan-progress";
import { Card, EmptyState, ErrorBanner, PageHeader, Tag } from "@/components/ui";
import { api } from "@/lib/api";
import { timeAgo } from "@/lib/format";
import type { Scan } from "@/lib/types";

interface NetworkOptions {
  scan_types: { id: string; description: string }[];
  authorization_text: string;
  default_ports: number[];
  max_hosts: number;
  max_ports: number;
  public_targets_allowed: boolean;
}

interface HostService {
  port: number;
  protocol: string;
  state: string;
  service: string;
  version: string;
  banner: string;
}

interface Host {
  id: string;
  ip: string;
  hostname: string;
  os_guess: string;
  device_type: string;
  status: string;
  latency_ms: number | null;
  scanned_at: string;
  services: HostService[];
  findings: Record<string, number>;
}

export default function NetworkPage() {
  const { id } = useParams<{ id: string }>();
  const [options, setOptions] = useState<NetworkOptions | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [activeScan, setActiveScan] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);

  const [target, setTarget] = useState("");
  const [scanType, setScanType] = useState("port_scan");
  const [ports, setPorts] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [statement, setStatement] = useState("");
  const [starting, setStarting] = useState(false);

  const load = useCallback(async () => {
    try {
      const [opts, sc, inv] = await Promise.all([
        api<NetworkOptions>("/api/network/options"),
        api<Scan[]>(`/api/projects/${id}/network/scans`),
        api<Host[]>(`/api/projects/${id}/network/hosts`),
      ]);
      setOptions(opts);
      setScans(sc);
      setHosts(inv);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load network data");
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
      const scan = await api<Scan>("/api/network/scans", {
        method: "POST",
        body: {
          project_id: id,
          target,
          scan_type: scanType,
          ports: ports || undefined,
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
      <PageHeader title="Network scanning" subtitle="Authorized discovery, port/service inventory and audit" />
      <ErrorBanner message={error} />

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Run a network scan">
          <form onSubmit={startScan} className="space-y-3">
            <label className="block text-sm">
              <span className="mb-1 block text-xs text-muted">Target (IP, CIDR or hostname)</span>
              <input className="input" required value={target} onChange={(e) => setTarget(e.target.value)} />
            </label>
            <label className="block text-sm">
              <span className="mb-1 block text-xs text-muted">Scan type</span>
              <select className="input" value={scanType} onChange={(e) => setScanType(e.target.value)}>
                {options.scan_types.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.id} — {t.description}
                  </option>
                ))}
              </select>
            </label>
            <label className="block text-sm">
              <span className="mb-1 block text-xs text-muted">
                Ports (e.g. 22,80,443 or 1-1024; default is the top {options.default_ports.length} ports)
              </span>
              <input className="input" value={ports} onChange={(e) => setPorts(e.target.value)} />
            </label>
            <div className="rounded-md border border-border bg-surface-2 p-3 text-xs text-muted">
              {options.authorization_text}
            </div>
            <label className="flex items-start gap-2 text-sm">
              <input type="checkbox" className="mt-1" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} />
              I confirm I am authorized to scan this target.
            </label>
            <label className="block text-sm">
              <span className="mb-1 block text-xs text-muted">Authorization statement (20+ characters)</span>
              <textarea
                className="input"
                rows={2}
                required
                minLength={20}
                value={statement}
                onChange={(e) => setStatement(e.target.value)}
                placeholder="e.g. I own this network / this is my home lab / written authorization ref #123"
              />
            </label>
            <button className="btn btn-primary" disabled={starting || !authorized}>
              <Radar className="h-4 w-4" aria-hidden /> Start scan
            </button>
          </form>
          {activeScan && (
            <div className="mt-5 border-t border-border pt-4">
              <ScanProgress scanId={activeScan} scannerNames={{ network: "Network scanner" }} onFinished={load} />
            </div>
          )}
        </Card>

        <Card title="Scan history">
          {scans.length === 0 ? (
            <p className="text-sm text-muted">No network scans yet.</p>
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
                  <span className="flex items-center gap-2">
                    <a className="text-xs text-muted hover:underline" href={`/api/network/scans/${s.id}/export?format=json`}>
                      <Download className="mr-1 inline h-3 w-3" aria-hidden />
                      JSON
                    </a>
                    <a className="text-xs text-muted hover:underline" href={`/api/network/scans/${s.id}/export?format=csv`}>
                      CSV
                    </a>
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <Card title="Host inventory" className="mt-6">
        {hosts.length === 0 ? (
          <EmptyState title="No hosts inventoried yet" hint="Run a network scan to populate this inventory." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr>
                  <th className="th">Host</th>
                  <th className="th">Device</th>
                  <th className="th">Status</th>
                  <th className="th">Open ports</th>
                  <th className="th">Findings</th>
                  <th className="th">Last seen</th>
                </tr>
              </thead>
              <tbody>
                {hosts.map((h) => (
                  <Fragment key={h.id}>
                    <tr
                      className="cursor-pointer border-t border-border hover:bg-surface-2"
                      onClick={() => setExpanded(expanded === h.id ? null : h.id)}
                    >
                      <td className="td">{h.hostname || h.ip}</td>
                      <td className="td">{h.device_type || "unknown"}</td>
                      <td className="td">
                        <Tag>{h.status}</Tag>
                      </td>
                      <td className="td tabular-nums">{h.services.length}</td>
                      <td className="td tabular-nums">
                        {Object.values(h.findings).reduce((a, b) => a + b, 0)}
                      </td>
                      <td className="td">{timeAgo(h.scanned_at)}</td>
                    </tr>
                    {expanded === h.id && (
                      <tr className="border-t border-border bg-surface-2">
                        <td className="td" colSpan={6}>
                          {h.services.length === 0 ? (
                            <p className="text-xs text-muted">No open ports observed.</p>
                          ) : (
                            <table className="w-full">
                              <thead>
                                <tr>
                                  <th className="th">Port</th>
                                  <th className="th">Protocol</th>
                                  <th className="th">Service</th>
                                  <th className="th">Version</th>
                                </tr>
                              </thead>
                              <tbody>
                                {h.services.map((s) => (
                                  <tr key={s.port}>
                                    <td className="td">{s.port}</td>
                                    <td className="td">{s.protocol}</td>
                                    <td className="td">{s.service}</td>
                                    <td className="td">{s.version}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          )}
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </>
  );
}
