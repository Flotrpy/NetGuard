/** Unified-diff viewer: added/removed lines are marked with +/- as well as colour. */
export function DiffView({ diff }: { diff: string }) {
  const lines = diff.split("\n");
  return (
    <pre className="max-h-96 overflow-auto rounded-md border border-border bg-bg p-3 font-mono text-xs leading-5" aria-label="Proposed changes">
      {lines.map((line, i) => {
        let cls = "text-fg/80";
        if (line.startsWith("+++") || line.startsWith("---")) cls = "font-semibold text-muted";
        else if (line.startsWith("@@")) cls = "text-accent";
        else if (line.startsWith("+")) cls = "bg-ok/10 text-ok";
        else if (line.startsWith("-")) cls = "bg-sev-critical/10 text-sev-critical";
        return (
          <div key={i} className={cls}>
            {line || " "}
          </div>
        );
      })}
    </pre>
  );
}
