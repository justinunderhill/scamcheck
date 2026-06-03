// Small, consistent inline SVG icons. Stroke-based so they inherit currentColor
// and stay crisp at any size. No icon-library dependency.
import type { SVGProps } from "react";

type IconProps = SVGProps<SVGSVGElement>;

const base = (props: IconProps) => ({
  width: 24,
  height: 24,
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.8,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
  ...props,
});

export const ShieldCheck = (p: IconProps) => (
  <svg {...base(p)}>
    <path d="M12 3 5 6v5c0 4.2 2.9 7.6 7 9 4.1-1.4 7-4.8 7-9V6l-7-3Z" />
    <path d="m9 11.5 2 2 4-4.5" />
  </svg>
);

export const ShieldAlert = (p: IconProps) => (
  <svg {...base(p)}>
    <path d="M12 3 5 6v5c0 4.2 2.9 7.6 7 9 4.1-1.4 7-4.8 7-9V6l-7-3Z" />
    <path d="M12 8.5v3.5" />
    <path d="M12 15h.01" />
  </svg>
);

export const ShieldX = (p: IconProps) => (
  <svg {...base(p)}>
    <path d="M12 3 5 6v5c0 4.2 2.9 7.6 7 9 4.1-1.4 7-4.8 7-9V6l-7-3Z" />
    <path d="m9.5 9.5 5 5" />
    <path d="m14.5 9.5-5 5" />
  </svg>
);

export const Search = (p: IconProps) => (
  <svg {...base(p)}>
    <circle cx="11" cy="11" r="7" />
    <path d="m20 20-3.2-3.2" />
  </svg>
);

export const Check = (p: IconProps) => (
  <svg {...base(p)}>
    <path d="m5 12.5 4.5 4.5L19 7" />
  </svg>
);

export const Dash = (p: IconProps) => (
  <svg {...base(p)}>
    <path d="M6 12h12" />
  </svg>
);

export const Chevron = (p: IconProps) => (
  <svg {...base(p)}>
    <path d="m8 10 4 4 4-4" />
  </svg>
);

export const Sparkle = (p: IconProps) => (
  <svg {...base(p)}>
    <path d="M12 4c.4 3.2 1.4 4.2 4.6 4.6C13.4 9 12.4 10 12 13.2 11.6 10 10.6 9 7.4 8.6 10.6 8.2 11.6 7.2 12 4Z" />
    <path d="M18.5 13.5c.2 1.6.7 2.1 2.3 2.3-1.6.2-2.1.7-2.3 2.3-.2-1.6-.7-2.1-2.3-2.3 1.6-.2 2.1-.7 2.3-2.3Z" />
  </svg>
);

export const ArrowRight = (p: IconProps) => (
  <svg {...base(p)}>
    <path d="M5 12h14" />
    <path d="m13 6 6 6-6 6" />
  </svg>
);
