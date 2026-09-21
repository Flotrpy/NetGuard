"use client";

import { Moon, Sun } from "lucide-react";
import { useEffect, useState } from "react";

export function ThemeToggle() {
  const [dark, setDark] = useState(true);

  useEffect(() => {
    setDark(document.documentElement.classList.contains("dark"));
  }, []);

  function toggle() {
    const next = !dark;
    setDark(next);
    document.documentElement.classList.toggle("dark", next);
    try {
      localStorage.setItem("ng-theme", next ? "dark" : "light");
    } catch {
      /* storage unavailable: theme just won't persist */
    }
  }

  return (
    <button className="btn" onClick={toggle} aria-label="Toggle colour theme" title="Toggle theme">
      {dark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
    </button>
  );
}

/** Runs before hydration to avoid a flash of the wrong theme. Dark is the default. */
export const themeInitScript = `try{var t=localStorage.getItem('ng-theme');if(t!=='light'){document.documentElement.classList.add('dark')}}catch(e){document.documentElement.classList.add('dark')}`;
