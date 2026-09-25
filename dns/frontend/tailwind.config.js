/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        primary: "#0F172A",
        "on-primary": "#FFFFFF",
        secondary: "#1E293B",
        accent: "#22C55E",
        background: "#020617",
        foreground: "#F8FAFC",
        muted: "#1A1E2F",
        border: "#334155",
        destructive: "#EF4444",
        ring: "#0F172A",
        "brand-orange": "#F97316",
        "brand-red": "#EF4444",
        "brand-green": "#22C55E",
        "brand-blue": "#3B82F6",
      },
      fontFamily: {
        sans: ["Fira Sans", "sans-serif"],
        mono: ["Fira Code", "monospace"],
      },
      boxShadow: {
        card: "0 1px 3px 0 rgba(0, 0, 0, 0.5), 0 1px 2px 0 rgba(0, 0, 0, 0.3)",
        "card-hover": "0 4px 6px -1px rgba(0, 0, 0, 0.5), 0 2px 4px -1px rgba(0, 0, 0, 0.3)",
      },
    },
  },
  plugins: [],
}
