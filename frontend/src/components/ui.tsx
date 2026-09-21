import clsx from "clsx";
import {
  AlertOctagon,
  AlertTriangle,
  CheckCircle2,
  CircleDashed,
  Info,
  Loader2,
  MinusCircle,
  ShieldAlert,
} from "lucide-react";
import type { ReactNode } from "react";
import { severityLabel } from "@/lib/format";
import { STATUS_LABELS, type FindingStatus, type Severity } from "@/lib/types";

// Static class strings so Tailwind can see them at build time.
const SEVERITY_STYLES: Record<Severity, string> = {
  critical: "bg-sev-critical/15 text-sev-critical border-sev-critical/30",
  high: "bg-sev-high/15 text-sev-high border-sev-high/30",
  medium: "bg-sev-medium/15 text-sev-medium border-sev-medium/30",
  low: "bg-sev-low/15 text-sev-low border-sev-low/30",
  info: "bg-sev-info/15 text-sev-info border-sev-info/30",
};

const SEVERITY_ICONS: Record<Severity, typeof Info> = {
  critical: AlertOctagon,
  high: ShieldAlert,
  medium: AlertTriangle,
  low: Info,
  info: MinusCircle,
};

/** Severity is conveyed by icon + text as well as colour (not colour alone). */
export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  const Icon = SEVERITY_ICONS[severity];
  return (
    <span
      className={clsx(
        "inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-xs font-semibold",
        SEVERITY_STYLES[severity],
        className,
      )}
    >
      <Icon className="h-3 w-3" aria-hidden />
      {severityLabel(severity)}
    </span>
  );
}

const STATUS_STYLES: Record<FindingStatus, string> = {
  open: "text-sev-high",
  confirmed: "text-sev-critical",
  in_progress: "text-sev-low",
  fixed: "text-ok",
  false_positive: "text-muted",
  accepted_risk: "text-muted",
};

export function StatusBadge({ status }: { status: FindingStatus }) {
  return (
    <span className={clsx("inline-flex items-center gap-1 text-xs font-medium", STATUS_STYLES[status])}>
      {status === "fixed" ? <CheckCircle2 className="h-3 w-3" aria-hidden /> : <CircleDashed className="h-3 w-3" aria-hidden />}
      {STATUS_LABELS[status]}
    </span>
  );
}

export function Card({
  title,
  action,
  children,
  className,
}: {
  title?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={clsx("card", className)}>
      {(title || action) && (
        <header className="flex items-center justify-between border-b border-border px-4 py-2.5">
          <h2 className="text-sm font-semibold">{title}</h2>
          {action}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function PageHeader({
  title,
  subtitle,
  actions,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-wrap items-start justify-between gap-3">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-muted">{subtitle}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}

export function ProgressBar({
  percent,
  state,
}: {
  percent: number;
  state?: "pending" | "running" | "completed" | "failed" | "skipped" | "unavailable";
}) {
  const color =
    state === "failed" ? "bg-sev-critical" : state === "completed" ? "bg-ok" : "bg-accent";
  return (
    <div
      role="progressbar"
      aria-valuenow={percent}
      aria-valuemin={0}
      aria-valuemax={100}
      className="h-2 w-full overflow-hidden rounded bg-surface-2"
    >
      <div className={clsx("h-full transition-all", color)} style={{ width: `${percent}%` }} />
    </div>
  );
}

export function Spinner({ label = "Loading" }: { label?: string }) {
  return (
    <span className="inline-flex items-center gap-2 text-sm text-muted" role="status">
      <Loader2 className="h-4 w-4 animate-spin" aria-hidden /> {label}…
    </span>
  );
}

export function ErrorBanner({ message }: { message: string | null | undefined }) {
  if (!message) return null;
  return (
    <div role="alert" className="mb-4 rounded-md border border-sev-critical/40 bg-sev-critical/10 px-3 py-2 text-sm text-sev-critical">
      {message}
    </div>
  );
}

export function EmptyState({
  title,
  hint,
  action,
}: {
  title: string;
  hint?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center gap-2 px-6 py-10 text-center">
      <p className="text-sm font-medium">{title}</p>
      {hint && <p className="max-w-md text-sm text-muted">{hint}</p>}
      {action}
    </div>
  );
}

export function Tag({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <span className={clsx("rounded border border-border bg-surface-2 px-1.5 py-0.5 font-mono text-xs text-muted", className)}>
      {children}
    </span>
  );
}
