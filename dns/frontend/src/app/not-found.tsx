import Link from "next/link";
import { ShieldAlert, ArrowLeft, Home } from "lucide-react";

export default function NotFound() {
  return (
    <div className="min-h-screen flex items-center justify-center p-6 bg-[#FAFAFA] dark:bg-[#07090E] text-[#1A1A1A] dark:text-[#F3F4F6]">
      <div className="w-full max-w-md p-8 rounded-xl border border-border bg-card shadow-lg text-center space-y-6">
        <div className="w-16 h-16 mx-auto rounded-2xl bg-destructive/10 border border-destructive/20 flex items-center justify-center text-destructive">
          <ShieldAlert className="w-8 h-8" />
        </div>

        <div className="space-y-2">
          <span className="text-xs font-mono font-semibold uppercase tracking-widest text-primary">
            HTTP 404
          </span>
          <h1 className="text-2xl font-bold tracking-tight text-foreground font-sans">
            Page Not Found
          </h1>
          <p className="text-xs text-muted-foreground max-w-xs mx-auto">
            The requested route or resource does not exist in the DNS Threat Detection platform.
          </p>
        </div>

        <div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-2">
          <Link
            href="/overview"
            className="w-full sm:w-auto flex items-center justify-center gap-1.5 px-4 py-2 rounded-lg bg-primary text-primary-foreground text-xs font-medium hover:opacity-90 transition-opacity cursor-pointer"
          >
            <Home className="w-3.5 h-3.5" />
            <span>Overview Dashboard</span>
          </Link>
          <Link
            href="/home"
            className="w-full sm:w-auto flex items-center justify-center gap-1.5 px-4 py-2 rounded-lg border border-border bg-secondary hover:bg-accent text-xs font-medium text-foreground transition-colors cursor-pointer"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Command Hub</span>
          </Link>
        </div>
      </div>
    </div>
  );
}
