"use client";

import { Download, Play, Upload } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useState, type FormEvent } from "react";
import { ScanProgress } from "@/components/scan-progress";
import { Card, EmptyState, ErrorBanner, PageHeader, SeverityBadge, Spinner, Tag } from "@/components/ui";
import { api } from "@/lib/api";
import { timeAgo, totalCount } from "@/lib/format";
import { SEVERITIES, type Project, type Repository, type Scan, type ScannerInfo } from "@/lib/types";

export default function ProjectDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [project, setProject] = useState<Project | null>(null);
  const [repos, setRepos] = useState<Repository[]>([]);
  const [scanners, setScanners] = useState<ScannerInfo[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [activeScan, setActiveScan] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [repoId, setRepoId] = useState("");
  const [newRepo, setNewRepo] = useState("");
  const [uploading, setUploading] = useState(false);
  const [reportFormat, setReportFormat] = useState("html");
  const [reportMinSeverity, setReportMinSeverity] = useState("info");
  const [reportIncludeFixed, setReportIncludeFixed] = useState(true);

  const canWrite = project?.role !== "viewer";

  const load = useCallback(async () => {
    try {
      const [p, r, s, sc] = await Promise.all([
        api<Project>(`/api/projects/${id}`),
        api<Repository[]>(`/api/projects/${id}/repositories`),
        api<ScannerInfo[]>("/api/scanners"),
        api<Scan[]>(`/api/projects/${id}/scans`),
      ]);
      setProject(p);
      setRepos(r);
      setScanners(s);
      setScans(sc);
      setRepoId((cur) => cur || r[0]?.id || "");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load project");
    }
  }, [id]);
  useEffect(() => {
    load();
  }, [load]);

  const codeScanners = scanners.filter((s) => s.supported_inputs.includes("source"));

  async function addRepo(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const r = await api<Repository>(`/api/projects/${id}/repositories`, { method: "POST", body: { name: newRepo } });
      setNewRepo("");
      setRepoId(r.id);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not add repository");
    }
  }

  async function upload(file: File) {
    if (!repoId) return;
    setUploading(true);
    setError(null);
    try {
      const form = new FormData();
      form.append("file", file);
      await api(`/api/repositories/${repoId}/upload`, { method: "POST", form });
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Upload failed");
    } finally {
      setUploading(false);
    }
  }

  async function startScan() {
    setError(null);
    try {
      const scan = await api<Scan>(`/api/projects/${id}/scans`, {
        method: "POST",
        body: { scanners: [...selected], repository_id: repoId },
      });
      setActiveScan(scan.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not start scan");
    }
  }

  if (!project) return error ? <ErrorBanner message={error} /> : <Spinner />;

  const repo = repos.find((r) => r.id === repoId);
  const names = Object.fromEntries(scanners.map((s) => [s.name, s.display_name]));
  const reportQuery = new URLSearchParams({
    format: reportFormat,
    min_severity: reportMinSeverity,
    include_fixed: String(reportIncludeFixed),
  });
  const reportHref = `/api/projects/${project.id}/report?${reportQuery.toString()}`;

  return (
    <>
      <PageHeader
        title={project.name}
        subtitle={project.description || "Project overview"}
        actions={
          <>
            {project.role === "owner" && (
              <Link className="btn" href={`/projects/${project.id}/settings`}>
                Settings
              </Link>
            )}
            <Link className="btn" href={`/projects/${project.id}/network`}>
              Network
            </Link>
            <Link className="btn" href={`/projects/${project.id}/packets`}>
              Packets
            </Link>
            <Link className="btn" href={`/projects/${project.id}/api-scanner`}>
              API scanner
            </Link>
            <Link className="btn" href={`/findings?project_id=${project.id}`}>
              View findings
            </Link>
          </>
        }
      />
      <ErrorBanner message={error} />

      <div className="mb-6 grid grid-cols-2 gap-3 md:grid-cols-5">
        {SEVERITIES.map((s) => (
          <div key={s} className="card p-3">
            <SeverityBadge severity={s} />
            <p className="mt-1 text-2xl font-semibold tabular-nums">{project.open_findings[s]}</p>
          </div>
        ))}
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Repositories">
          {repos.length === 0 ? (
            <EmptyState title="No repositories" hint="Add a repository, then upload its source as a .zip or .tar.gz." />
          ) : (
            <ul className="mb-4 divide-y divide-border">
              {repos.map((r) => (
                <li key={r.id} className="flex items-center justify-between py-2 text-sm">
                  <label className="flex items-center gap-2">
                    <input type="radio" name="repo" checked={repoId === r.id} onChange={() => setRepoId(r.id)} />
                    {r.name}
                  </label>
                  <span className="flex items-center gap-2">
                    {r.latest_snapshot_id && (
                      <>
                        <a className="text-xs text-muted hover:underline" href={`/api/repositories/${r.id}/sbom?format=cyclonedx`}>
                          SBOM (CycloneDX)
                        </a>
                        <a className="text-xs text-muted hover:underline" href={`/api/repositories/${r.id}/sbom?format=spdx`}>
                          SBOM (SPDX)
                        </a>
                      </>
                    )}
                    <Tag>{r.latest_snapshot_id ? "snapshot ready" : "no code yet"}</Tag>
                  </span>
                </li>
              ))}
            </ul>
          )}
          {canWrite && (
            <div className="space-y-3">
              <form onSubmit={addRepo} className="flex gap-2">
                <input className="input" placeholder="Repository name" required value={newRepo} onChange={(e) => setNewRepo(e.target.value)} />
                <button className="btn">Add</button>
              </form>
              {repo && (
                <label className="btn cursor-pointer">
                  <Upload className="h-4 w-4" aria-hidden />
                  {uploading ? "Uploading…" : `Upload code for “${repo.name}”`}
                  <input
                    type="file"
                    accept=".zip,.tar,.gz,.tgz"
                    className="sr-only"
                    disabled={uploading}
                    onChange={(e) => {
                      const f = e.target.files?.[0];
                      if (f) upload(f);
                      e.target.value = "";
                    }}
                  />
                </label>
              )}
              <p className="text-xs text-muted">
                Archives are extracted server-side with path, symlink and size checks. Only upload code you are
                authorized to analyze.
              </p>
            </div>
          )}
        </Card>

        <Card title="Run a scan">
          <div className="space-y-2">
            {codeScanners.map((s) => (
              <label key={s.name} className={`flex items-start gap-2 text-sm ${s.available ? "" : "opacity-60"}`}>
                <input
                  type="checkbox"
                  className="mt-1"
                  disabled={!s.available || !canWrite}
                  checked={selected.has(s.name)}
                  onChange={(e) => {
                    const next = new Set(selected);
                    if (e.target.checked) next.add(s.name);
                    else next.delete(s.name);
                    setSelected(next);
                  }}
                />
                <span>
                  <span className="font-medium">{s.display_name}</span>{" "}
                  {!s.available && <Tag>{s.status_note || "unavailable"}</Tag>}
                  <span className="block text-xs text-muted">{s.description}</span>
                </span>
              </label>
            ))}
          </div>
          <button
            className="btn btn-primary mt-4"
            disabled={!canWrite || selected.size === 0 || !repo?.latest_snapshot_id}
            onClick={startScan}
          >
            <Play className="h-4 w-4" aria-hidden /> Start scan
          </button>
          {repo && !repo.latest_snapshot_id && (
            <p className="mt-2 text-xs text-muted">Upload code for this repository before scanning.</p>
          )}
          {activeScan && (
            <div className="mt-5 border-t border-border pt-4">
              <ScanProgress
                scanId={activeScan}
                scannerNames={names}
                onFinished={() => {
                  load();
                }}
              />
            </div>
          )}
        </Card>
      </div>

      <Card title="Reports" className="mt-6">
        <p className="mb-3 text-sm text-muted">
          Export a security assessment report covering findings, verification results, dependency and
          network detail. Secret values are never included.
        </p>
        <div className="flex flex-wrap items-end gap-3">
          <label className="text-sm">
            <span className="mb-1 block text-xs text-muted">Format</span>
            <select className="input" value={reportFormat} onChange={(e) => setReportFormat(e.target.value)}>
              <option value="html">HTML</option>
              <option value="pdf">PDF</option>
              <option value="json">JSON</option>
              <option value="csv">CSV</option>
            </select>
          </label>
          <label className="text-sm">
            <span className="mb-1 block text-xs text-muted">Minimum severity</span>
            <select className="input" value={reportMinSeverity} onChange={(e) => setReportMinSeverity(e.target.value)}>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </label>
          <label className="flex items-center gap-2 pb-2 text-sm">
            <input
              type="checkbox"
              checked={reportIncludeFixed}
              onChange={(e) => setReportIncludeFixed(e.target.checked)}
            />
            Include fixed findings
          </label>
          <a className="btn btn-primary" href={reportHref}>
            <Download className="h-4 w-4" aria-hidden /> Download report
          </a>
        </div>
      </Card>

      <Card title="Scan history" className="mt-6">
        {scans.length === 0 ? (
          <p className="text-sm text-muted">No scans have been run for this project.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr>
                  <th className="th">When</th>
                  <th className="th">Scanners</th>
                  <th className="th">Status</th>
                  <th className="th">Findings</th>
                  <th className="th">Trigger</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((s) => (
                  <tr key={s.id} className="border-t border-border">
                    <td className="td">{timeAgo(s.created_at)}</td>
                    <td className="td">{s.scanners.map((n) => names[n] ?? n).join(", ")}</td>
                    <td className="td">{s.status}</td>
                    <td className="td tabular-nums">{s.summary.severity ? totalCount(s.summary.severity) : "–"}</td>
                    <td className="td">
                      <Tag>{s.trigger}</Tag>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </>
  );
}
