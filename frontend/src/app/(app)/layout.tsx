import type { ReactNode } from "react";
import { Shell } from "@/components/shell";
import { AuthProvider } from "@/lib/auth";

export default function AppLayout({ children }: { children: ReactNode }) {
  return (
    <AuthProvider>
      <Shell>{children}</Shell>
    </AuthProvider>
  );
}
