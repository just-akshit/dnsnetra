/**
 * Static abstract DNS -> intelligence -> verdict composition. Standalone and
 * logo-free: swap this component for brand art without touching the layout.
 */
const mono = { fontFamily: "var(--font-geist-mono), ui-monospace, monospace" }

export function AuthVisual({ compact = false }: { compact?: boolean }) {
  return (
    <svg
      aria-hidden="true"
      focusable="false"
      viewBox={compact ? "40 205 560 290" : "0 0 640 760"}
      preserveAspectRatio="xMidYMid slice"
      className="h-full w-full"
    >
      <defs>
        <pattern id="auth-dots" width="32" height="32" patternUnits="userSpaceOnUse">
          <circle cx="1" cy="1" r="1" fill="var(--auth-ink)" opacity="0.16" />
        </pattern>
      </defs>
      <rect width="640" height="760" fill="url(#auth-dots)" />

      {/* ambient domain fragments */}
      <g fill="var(--auth-muted)" fontSize="11" opacity="0.55" style={mono}>
        <text x="30" y="316">cdn.assets.example</text>
        <text x="448" y="182">mail.example.org</text>
        <text x="30" y="604">api.internal.example</text>
        <text x="452" y="708">a8f3k2.example.biz</text>
        <text x="500" y="560">ns1.example.net</text>
      </g>

      {/* query path: client -> domain */}
      <path d="M110 120 C110 190 330 170 330 250" fill="none" stroke="var(--auth-ink)" strokeOpacity="0.45" strokeDasharray="3 5" />
      <circle cx="110" cy="120" r="5" fill="var(--auth-panel)" stroke="var(--auth-ink)" />
      <text x="124" y="124" fontSize="11" fill="var(--auth-muted)" style={mono}>client</text>
      <text x="175" y="152" fontSize="11" fill="var(--auth-muted)" style={mono}>dns query</text>

      {/* domain */}
      <rect x="226" y="232" width="208" height="38" rx="19" fill="var(--auth-panel)" stroke="var(--auth-ink)" />
      <text x="330" y="256" textAnchor="middle" fontSize="12" fill="var(--auth-ink)" style={mono}>secure-login.example.net</text>

      {/* fan-out to intelligence signals */}
      <g fill="none" stroke="var(--auth-ink)" strokeOpacity="0.4">
        <path d="M330 270 C330 345 140 345 140 430" />
        <path d="M330 270 C330 345 520 345 520 430" />
        <path d="M140 430 C140 545 330 535 330 618" />
        <path d="M520 430 C520 545 330 535 330 618" />
      </g>
      <path d="M330 270 L330 450 L330 618" fill="none" stroke="var(--auth-accent)" strokeWidth="1.5" />

      {[
        [140, "reputation", false],
        [330, "threat intel", true],
        [520, "lexical", false],
      ].map(([x, label, hit]) => (
        <g key={label as string}>
          <circle cx={x as number} cy={hit ? 450 : 430} r="5" fill={hit ? "var(--auth-accent)" : "var(--auth-panel)"} stroke={hit ? "var(--auth-accent)" : "var(--auth-ink)"} />
          <text x={x as number} y={hit ? 478 : 458} textAnchor="middle" fontSize="11" fill="var(--auth-muted)" style={mono}>{label as string}</text>
        </g>
      ))}

      {/* verdict */}
      <circle cx="330" cy="640" r="22" fill="var(--auth-panel)" stroke="var(--auth-accent)" strokeWidth="1.5" />
      <circle cx="330" cy="640" r="6" fill="var(--auth-accent)" />
      <text x="366" y="636" fontSize="11" fill="var(--auth-muted)" style={mono}>verdict</text>
      <text x="366" y="654" fontSize="12" fill="var(--auth-accent)" style={mono}>review</text>
    </svg>
  )
}
