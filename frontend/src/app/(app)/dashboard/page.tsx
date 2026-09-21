"use client";

import { AlertTriangle, CheckCircle2, CircleDashed, MinusCircle } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";
import { TrendChart } from "@/components/trend-chart";
import { Card, EmptyState, ErrorBanner, PageHeader, SeverityBadge, Spinner } from "@/components/ui";
import { api } from "@/lib/api";
import { severityLabel, timeAgo, totalCount } from "@/lib/format";
import { SEVERITIES, type Dashboard, type ModuleStatus, type Project, type Severity } from "@/lib/types";

const SEV_TEXT: Record<Severity, string> = {
  critical: "text-sev-critical",
  high: "text-sev-high",
  medium: "text-sev-medium",
  low: "text-sev-low",
  info: "text-sev-info",
};

const GROUPS: { title: string; scanners: string[] }[] = [
  { title: "Code security", scanners: ["sast", "dependencies", "secrets"] },
  { title: "Network", scanners: ["network", "packets"] },
  { title: "Containers", scanners: ["docker"] },
  { title: "Infrastructure", scanners: ["iac"] },
  { title: "APIs", scanners: ["api"] },
];

function ModuleRow({ m }: { m: ModuleStatus }) {
  let icon = <CheckCircle2 className="h-4 w-4 text-ok" aria-hidden />;
  let text = "No open findings";
  if (m.status === "attention") {
    icon = <AlertTriangle className="h-4 w-4 text-sev-high" aria-hidden />;
    text = `${m.open_findings} open finding${m.open_findings === 1 ? "" : "s"}`;
  } else if (m.status === "not_scanned") {
    icon = <CircleDashed className="h-4 w-4 text-muted" aria-hidden />;
    text = "Not scanned yet";
  } else if (m.status === "unavailable") {
    icon = <MinusCircle className="h-4 w-4 text-muted" aria-hidden />;
    text = "Planned: not available yet";
  }
  return (
    <li className="flex items-center gap-2 py-1 text-sm">
      {icon}
      <span className="flex-1">{m.name}</span>
      <span className="text-xs text-muted">{text}</span>
    </li>
  );
}

export default function DashboardPage() {
  const [projects, setProjects] = useState<Project[] | null>(null);
  const [projectId, setProjectId] = useState("");
  const [data, setData] = useState<Dashboard | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api<Project[]>("/api/projects").then(setProjects).catch((e) => setError(e.message));
  }, []);

  useEffect(() => {
    setData(null);
    api<Dashboard>("/api/dashboard", { query: { project_id: projectId } })
      .then(setData)
      .catch((e) => setError(e.message));
  }, [projectId]);

  if (projects && projects.length === 0) {
    return (
      <>
        <PageHeader title="Dashboard" />
        <Card>
          <EmptyState
            title="Welcome to NetGuard"
            hint="Create a project, upload a repository and run your first scan to see security findings here."
            action={
              <Link href="/projects" className="btn btn-primary">
                Create a project
              </Link>
            }
          />
        </Card>
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Security dashboard"
        subtitle="Current findings across your projects"
        actions={
          <select
            className="input w-56"
            value={projectId}
            onChange={(e) => setProjectId(e.target.value)}
            aria-label="Project"
          >
            <option value="">All projects</option>
            {projects?.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        }
      />
      <ErrorBanner message={error} />
      {!data ? (
        <Spinner />
      ) : (
        <div className="space-y-6">
          <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
            {SEVERITIES.map((s) => (
              <Link
                key={s}
                href={`/findings?severity=${s}&status=open,confirmed,in_progress${projectId ? `&project_id=${projectId}` : ""}`}
                className="card p-4 transition hover:border-accent/60"
              >
                <SeverityBadge severity={s} />
                <p className={`mt-2 text-3xl font-semibold tabular-nums ${SEV_TEXT[s]}`}>{data.severity[s]}</p>
                <p className="text-xs text-muted">{severityLabel(s)} open</p>
              </Link>
            ))}
          </div>

          <div className="grid gap-6 lg:grid-cols-3">
            <Card title="Active findings, last 30 days" className="lg:col-span-2">
              <TrendChart data={data.trend} />
            </Card>
            <Card title="Remediation progress">
              {data.totals.remediation_progress === null ? (
                <p className="text-sm text-muted">Nothing to remediate yet.</p>
              ) : (
                <>
                  <p className="text-3xl font-semibold tabular-nums">
                    {Math.round(data.totals.remediation_progress * 100)}%
                  </p>
                  <p className="mt-1 text-sm text-muted">
                    {data.totals.fixed} fixed of {data.totals.fixed + data.totals.active} actionable findings
                  </p>
                </>
              )}
              <p className="mt-3 text-xs text-muted">
                This is the share of actionable findings that have been fixed. It is a progress
                measure, not a security score. {data.totals.triaged} finding
                {data.totals.triaged === 1 ? " is" : "s are"} triaged as false positive or accepted risk.
              </p>
            </Card>
          </div>

          <Card title="Security modules">
            <div className="grid gap-x-8 gap-y-4 md:grid-cols-2">
              {GROUPS.map((g) => (
                <div key={g.title}>
                  <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted">{g.title}</p>
                  <ul>
                    {g.scanners.map((name) => {
                      const m = data.modules.find((x) => x.scanner === name);
                      return m ? <ModuleRow key={name} m={m} /> : null;
                    })}
                  </ul>
                </div>
              ))}
            </div>
          </Card>

          <div className="grid gap-6 lg:grid-cols-2">
            <Card title="Recent scans">
              {data.recent_scans.length === 0 ? (
                <p className="text-sm text-muted">No scans yet.</p>
              ) : (
                <ul className="divide-y divide-border">
                  {data.recent_scans.map((s) => (
                    <li key={s.id} className="flex items-center justify-between py-2 text-sm">
                      <Link href={`/projects/${s.project_id}`} className="hover:text-accent">
                        {s.scanners.join(", ")}
                      </Link>
                      <span className="text-xs text-muted">
                        {s.status} · {totalCount(s.severity)} findings · {timeAgo(s.created_at)}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </Card>
            <Card title="Recently fixed">
              {data.recently_fixed.length === 0 ? (
                <p className="text-sm text-muted">Nothing fixed yet.</p>
              ) : (
                <ul className="divide-y divide-border">
                  {data.recently_fixed.map((f) => (
                    <li key={f.id} className="flex items-center gap-2 py-2 text-sm">
                      <CheckCircle2 className="h-4 w-4 text-ok" aria-hidden />
                      <Link href={`/findings/${f.id}`} className="flex-1 truncate hover:text-accent">
                        {f.title}
                      </Link>
                      <span className="text-xs text-muted">{timeAgo(f.resolved_at)}</span>
                    </li>
                  ))}
                </ul>
              )}
            </Card>
            <Card title="Affected repositories">
              {data.affected_repositories.length === 0 ? (
                <p className="text-sm text-muted">No repositories with open findings.</p>
              ) : (
                <ul className="divide-y divide-border">
                  {data.affected_repositories.map((r) => (
                    <li key={r.id} className="flex items-center justify-between py-2 text-sm">
                      <span>{r.name}</span>
                      <span className="text-xs text-muted">
                        {SEVERITIES.filter((s) => r.counts[s] > 0)
                          .map((s) => `${r.counts[s]} ${s}`)
                          .join(" · ")}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </Card>
            <Card title="Affected hosts">
              {data.affected_hosts.length === 0 ? (
                <p className="text-sm text-muted">No hosts with open findings. Run a network scan to inventory hosts.</p>
              ) : (
                <ul className="divide-y divide-border">
                  {data.affected_hosts.map((h) => (
                    <li key={h.id} className="flex items-center justify-between py-2 text-sm">
                      <span>{h.name}</span>
                      <span className="text-xs text-muted">{totalCount(h.counts)} findings</span>
                    </li>
                  ))}
                </ul>
              )}
            </Card>
          </div>
        </div>
      )}
    </>
  );
}
