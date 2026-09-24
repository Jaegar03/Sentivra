import type { Metadata } from "next";

import { AppShell } from "@/components/sentivra/app-shell";
import { THEME_BOOTSTRAP } from "@/components/sentivra/theme-toggle";
import { TooltipProvider } from "@/components/ui/tooltip";
import "./globals.css";

export const metadata: Metadata = {
  title: "SENTIVRA",
  description: "One Security Layer. Every Threat. Multi-layer detection dashboard (demonstration build).",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    // The bootstrap script sets the theme class before hydration, hence the warning suppression.
    <html lang="en" className="h-full antialiased" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_BOOTSTRAP }} />
      </head>
      <body className="min-h-full">
        <TooltipProvider>
          <AppShell>{children}</AppShell>
        </TooltipProvider>
      </body>
    </html>
  );
}
