import { ShieldCheck } from "lucide-react";
import type { ReactNode } from "react";
import { ThemeToggle } from "@/components/theme-toggle";
import { AuthProvider } from "@/lib/auth";

export default function AuthLayout({ children }: { children: ReactNode }) {
  return (
    <AuthProvider>
      <main className="relative flex min-h-screen items-center justify-center px-4">
        <div className="absolute right-4 top-4">
          <ThemeToggle />
        </div>
        <div className="w-full max-w-sm">
          <div className="mb-6 flex items-center justify-center gap-2">
            <ShieldCheck className="h-7 w-7 text-accent" aria-hidden />
            <span className="text-2xl font-semibold tracking-tight">NetGuard</span>
          </div>
          <p className="mb-6 text-center text-sm text-muted">
            Detect → Explain → Fix → Verify → Monitor
          </p>
          {children}
          <p className="mt-6 text-center text-xs text-muted">
            NetGuard is a defensive platform. Only assess systems you own or are explicitly authorized to
            test.
          </p>
        </div>
      </main>
    </AuthProvider>
  );
}
