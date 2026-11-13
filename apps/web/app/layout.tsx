import type { Metadata } from "next";
import Script from "next/script";
import { Geist, Geist_Mono, DM_Sans, Plus_Jakarta_Sans } from "next/font/google";
import localFont from "next/font/local";
import { ThemeProvider } from "@/components/theme-provider";
import { Toaster } from "@/components/ui/sonner";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

// Stardom (Fontshare / Indian Type Foundry) — Regular weight for the 190px DNSnetra wordmark.
const stardom = localFont({
  src: "./fonts/Stardom-Regular.woff2",
  variable: "--font-stardom",
  weight: "400",
  display: "swap",
});

// Kola kept available as a fallback variable.
const kola = localFont({
  src: "./fonts/Kola-Regular.woff2",
  variable: "--font-kola",
  weight: "400",
  display: "swap",
});

// Plus Jakarta Sans — crisp geometric-humanist UI font for auth labels, inputs, and controls.
const authSans = Plus_Jakarta_Sans({
  variable: "--font-auth-sans",
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
  display: "swap",
});

// Legacy brand variable kept for compatibility.
const brand = DM_Sans({
  variable: "--font-brand",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "DNSNetra — DNS Threat Detection",
  description:
    "Real-time DNS threat detection and network intelligence platform.",
};

const THEME_SCRIPT = `(function(){try{var t=localStorage.getItem("theme")||"system";var d=t==="dark"||(t==="system"&&window.matchMedia("(prefers-color-scheme: dark)").matches);if(d){document.documentElement.classList.add("dark");document.documentElement.style.colorScheme="dark";}else{document.documentElement.classList.remove("dark");document.documentElement.style.colorScheme="light";}}catch(e){}})();`;

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html
      lang="en"
      suppressHydrationWarning
      className={`${geistSans.variable} ${geistMono.variable} ${stardom.variable} ${kola.variable} ${authSans.variable} ${brand.variable} h-full antialiased`}
    >
      <body className="min-h-full flex flex-col">
        <Script
          id="dnsnetra-theme-init"
          strategy="beforeInteractive"
          dangerouslySetInnerHTML={{ __html: THEME_SCRIPT }}
        />
        <ThemeProvider
          defaultTheme="system"
          enableSystem
          disableTransitionOnChange
        >
          {children}
          <Toaster position="bottom-right" richColors />
        </ThemeProvider>
      </body>
    </html>
  );
}
