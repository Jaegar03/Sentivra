"use client";

import { useSyncExternalStore } from "react";
import { Moon, Sun } from "lucide-react";

import { Button } from "@/components/ui/button";

export const THEME_KEY = "sentivra-theme";

// Runs in <head> before first paint (see app/layout.tsx), so the saved or
// system theme is applied without a light/dark flash. Static string, no input.
export const THEME_BOOTSTRAP = `(function(){try{var t=localStorage.getItem('${THEME_KEY}');var d=t?t==='dark':window.matchMedia('(prefers-color-scheme: dark)').matches;document.documentElement.classList.toggle('dark',d);}catch(e){}})();`;

// The theme lives on <html class="dark">, outside React. Subscribe to it
// rather than copying it into state.
function subscribe(onChange: () => void) {
  const observer = new MutationObserver(onChange);
  observer.observe(document.documentElement, { attributes: true, attributeFilter: ["class"] });
  return () => observer.disconnect();
}
const isDark = () => document.documentElement.classList.contains("dark");
const serverSnapshot = () => false;

export function ThemeToggle() {
  const dark = useSyncExternalStore(subscribe, isDark, serverSnapshot);

  function toggle() {
    const next = !isDark();
    document.documentElement.classList.toggle("dark", next);
    try {
      localStorage.setItem(THEME_KEY, next ? "dark" : "light");
    } catch {
      // storage unavailable (private mode): the choice lasts for this page only
    }
  }

  return (
    <Button variant="ghost" size="icon-sm" onClick={toggle} aria-label="Toggle dark mode" title="Toggle dark mode">
      {dark ? <Sun /> : <Moon />}
    </Button>
  );
}
