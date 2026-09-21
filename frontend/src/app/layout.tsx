import type { Metadata } from "next";
import type { ReactNode } from "react";
import { themeInitScript } from "@/components/theme-toggle";
import "./globals.css";

export const metadata: Metadata = {
  title: "NetGuard: Detect, Explain, Fix, Verify, Monitor",
  description: "Defensive security detection, analysis and remediation platform",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeInitScript }} />
      </head>
      <body className="min-h-screen font-sans">{children}</body>
    </html>
  );
}
