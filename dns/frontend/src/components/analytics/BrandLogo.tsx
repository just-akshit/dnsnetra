import React from "react";

export const BrandLogo: React.FC<{ className?: string }> = ({ className = "w-7 h-7" }) => {
  return (
    <svg
      viewBox="0 0 48 48"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
    >
      <defs>
        <linearGradient id="shieldGrad" x1="6" y1="4" x2="42" y2="44" gradientUnits="userSpaceOnUse">
          <stop stopColor="#2563EB" />
          <stop offset="1" stopColor="#0EA5E9" />
        </linearGradient>
        <linearGradient id="coreGrad" x1="16" y1="16" x2="32" y2="32" gradientUnits="userSpaceOnUse">
          <stop stopColor="#60A5FA" />
          <stop offset="1" stopColor="#38BDF8" />
        </linearGradient>
      </defs>

      {/* Outer Hex/Shield Armor */}
      <path
        d="M24 4L8 10V22C8 32.5 14.8 42.2 24 44.5C33.2 42.2 40 32.5 40 22V10L24 4Z"
        fill="url(#shieldGrad)"
      />

      {/* Inner Radar & DNS Node Pulse */}
      <path
        d="M24 10L12 14.5V23C12 30.5 17.1 37.8 24 39.8C30.9 37.8 36 30.5 36 23V14.5L24 10Z"
        fill="#0F172A"
        fillOpacity="0.3"
      />

      {/* Concentric Signal Rings */}
      <circle cx="24" cy="24" r="9" stroke="url(#coreGrad)" strokeWidth="2" strokeDasharray="3 2" />
      <circle cx="24" cy="24" r="5" stroke="#FFFFFF" strokeWidth="1.8" />
      <circle cx="24" cy="24" r="2.2" fill="#FFFFFF" />

      {/* Signal Axis Rays */}
      <line x1="24" y1="12" x2="24" y2="15" stroke="url(#coreGrad)" strokeWidth="2" strokeLinecap="round" />
      <line x1="24" y1="33" x2="24" y2="36" stroke="url(#coreGrad)" strokeWidth="2" strokeLinecap="round" />
      <line x1="12" y1="24" x2="15" y2="24" stroke="url(#coreGrad)" strokeWidth="2" strokeLinecap="round" />
      <line x1="33" y1="24" x2="36" y2="24" stroke="url(#coreGrad)" strokeWidth="2" strokeLinecap="round" />
    </svg>
  );
};

export default BrandLogo;
