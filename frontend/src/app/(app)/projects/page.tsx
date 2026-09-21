"use client";

import { FolderGit2, Plus } from "lucide-react";
import Link from "next/link";
import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Card, EmptyState, ErrorBanner, PageHeader, SeverityBadge, Spinner } from "@/components/ui";
import { api } from "@/lib/api";
import { timeAgo } from "@/lib/format";
import { SEVERITIES, type Project } from "@/lib/types";

export default function ProjectsPage() {
  const [projects, setProjects] = useState<Project[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    api<Project[]>("/api/projects")
      .then(setProjects)
      .catch((e) => setError(e.message));
  }, []);
  useEffect(load, [load]);

  async function create(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api("/api/projects", { method: "POST", body: { name, description } });
      setName("");
      setDescription("");
      setShowForm(false);
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create project");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageHeader
        title="My projects"
        subtitle="Each project groups repositories, scans, findings and assets."
        actions={
          <button className="btn btn-primary" onClick={() => setShowForm((s) => !s)}>
            <Plus className="h-4 w-4" aria-hidden /> New project
          </button>
        }
      />
      <ErrorBanner message={error} />
      {showForm && (
        <form onSubmit={create} className="card mb-6 grid gap-4 p-4 md:grid-cols-[1fr_2fr_auto] md:items-end">
          <div>
            <label className="label" htmlFor="pname">
              Name
            </label>
            <input id="pname" className="input" required maxLength={200} value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div>
            <label className="label" htmlFor="pdesc">
              Description (optional)
            </label>
            <input id="pdesc" className="input" maxLength={2000} value={description} onChange={(e) => setDescription(e.target.value)} />
          </div>
          <button className="btn btn-primary" disabled={busy}>
            Create
          </button>
        </form>
      )}
      {!projects ? (
        <Spinner />
      ) : projects.length === 0 ? (
        <Card>
          <EmptyState title="No projects yet" hint="Create your first project to start scanning." />
        </Card>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {projects.map((p) => (
            <Link key={p.id} href={`/projects/${p.id}`} className="card block p-4 transition hover:border-accent/60">
              <div className="flex items-center gap-2">
                <FolderGit2 className="h-4 w-4 text-accent" aria-hidden />
                <h2 className="truncate font-semibold">{p.name}</h2>
              </div>
              {p.description && <p className="mt-1 line-clamp-2 text-sm text-muted">{p.description}</p>}
              <div className="mt-3 flex flex-wrap gap-1.5">
                {SEVERITIES.filter((s) => p.open_findings[s] > 0).map((s) => (
                  <span key={s} className="inline-flex items-center gap-1 text-xs">
                    <SeverityBadge severity={s} />
                    <span className="tabular-nums">{p.open_findings[s]}</span>
                  </span>
                ))}
                {SEVERITIES.every((s) => p.open_findings[s] === 0) && (
                  <span className="text-xs text-muted">No open findings</span>
                )}
              </div>
              <p className="mt-3 text-xs text-muted">
                {p.repository_count} repositor{p.repository_count === 1 ? "y" : "ies"} · last scan{" "}
                {timeAgo(p.last_scan_at)}
              </p>
            </Link>
          ))}
        </div>
      )}
    </>
  );
}
