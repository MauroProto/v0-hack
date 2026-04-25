import type { SVGProps } from "react"

type P = SVGProps<SVGSVGElement>

const base = {
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.6,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
}

export const Icon = {
  shield: (p: P) => (
    <svg {...base} {...p}>
      <path d="M12 3 4 6v6c0 5 3.5 8.5 8 9 4.5-.5 8-4 8-9V6l-8-3z" />
      <path d="m9 12 2 2 4-4" />
    </svg>
  ),
  chevDown: (p: P) => (
    <svg {...base} strokeWidth={1.8} {...p}>
      <path d="m6 9 6 6 6-6" />
    </svg>
  ),
  chevRight: (p: P) => (
    <svg {...base} strokeWidth={1.8} {...p}>
      <path d="m9 6 6 6-6 6" />
    </svg>
  ),
  search: (p: P) => (
    <svg {...base} {...p}>
      <circle cx="11" cy="11" r="7" />
      <path d="m20 20-3.5-3.5" />
    </svg>
  ),
  home: (p: P) => (
    <svg {...base} {...p}>
      <path d="m3 11 9-8 9 8" />
      <path d="M5 10v10a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V10" />
      <path d="M10 21v-6h4v6" />
    </svg>
  ),
  scan: (p: P) => (
    <svg {...base} {...p}>
      <rect x="3" y="3" width="7" height="7" rx="1.5" />
      <rect x="14" y="3" width="7" height="7" rx="1.5" />
      <rect x="3" y="14" width="7" height="7" rx="1.5" />
      <rect x="14" y="14" width="7" height="7" rx="1.5" />
    </svg>
  ),
  focus: (p: P) => (
    <svg {...base} {...p}>
      <path d="M3 7V5a2 2 0 0 1 2-2h2" />
      <path d="M17 3h2a2 2 0 0 1 2 2v2" />
      <path d="M21 17v2a2 2 0 0 1-2 2h-2" />
      <path d="M7 21H5a2 2 0 0 1-2-2v-2" />
      <path d="M8 12h8" />
    </svg>
  ),
  sparkle: (p: P) => (
    <svg {...base} {...p}>
      <path d="M12 3v4M12 17v4M3 12h4M17 12h4M5.6 5.6l2.8 2.8M15.6 15.6l2.8 2.8M5.6 18.4l2.8-2.8M15.6 8.4l2.8-2.8" />
    </svg>
  ),
  code: (p: P) => (
    <svg {...base} {...p}>
      <path d="m9 18-6-6 6-6" />
      <path d="m15 6 6 6-6 6" />
    </svg>
  ),
  book: (p: P) => (
    <svg {...base} {...p}>
      <path d="M4 4.5A2.5 2.5 0 0 1 6.5 2H20v18H6.5A2.5 2.5 0 0 0 4 22.5z" />
      <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20" />
    </svg>
  ),
  chartBar: (p: P) => (
    <svg {...base} {...p}>
      <path d="M3 3v18h18" />
      <rect x="7" y="12" width="3" height="6" />
      <rect x="12" y="8" width="3" height="10" />
      <rect x="17" y="5" width="3" height="13" />
    </svg>
  ),
  users: (p: P) => (
    <svg {...base} {...p}>
      <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
      <circle cx="9" cy="7" r="4" />
      <path d="M22 21v-2a4 4 0 0 0-3-3.87" />
      <path d="M16 3.13a4 4 0 0 1 0 7.75" />
    </svg>
  ),
  gear: (p: P) => (
    <svg {...base} {...p}>
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z" />
    </svg>
  ),
  moreH: (p: P) => (
    <svg {...base} {...p}>
      <circle cx="5" cy="12" r="1" />
      <circle cx="12" cy="12" r="1" />
      <circle cx="19" cy="12" r="1" />
    </svg>
  ),
  menu: (p: P) => (
    <svg {...base} {...p}>
      <path d="M3 6h18M3 12h18M3 18h18" />
    </svg>
  ),
  share: (p: P) => (
    <svg {...base} {...p}>
      <circle cx="18" cy="5" r="3" />
      <circle cx="6" cy="12" r="3" />
      <circle cx="18" cy="19" r="3" />
      <path d="m8.6 13.5 6.8 4" />
      <path d="m15.4 6.5-6.8 4" />
    </svg>
  ),
  export: (p: P) => (
    <svg {...base} {...p}>
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <path d="m7 10 5 5 5-5" />
      <path d="M12 15V3" />
    </svg>
  ),
  brackets: (p: P) => (
    <svg {...base} {...p}>
      <path d="m9 18-6-6 6-6" />
      <path d="m15 6 6 6-6 6" />
    </svg>
  ),
  wand: (p: P) => (
    <svg {...base} {...p}>
      <path d="m14 4 6 6-12 12-6-6z" />
      <path d="m13 5 6 6" />
      <path d="M18 3v2M22 4h-2M19 7h2" />
    </svg>
  ),
  key: (p: P) => (
    <svg {...base} {...p}>
      <circle cx="8" cy="15" r="4" />
      <path d="m10.85 12.15 7.4-7.4" />
      <path d="m18 5 3 3" />
      <path d="m15 8 2 2" />
    </svg>
  ),
  lock: (p: P) => (
    <svg {...base} {...p}>
      <rect x="4" y="11" width="16" height="10" rx="2" />
      <path d="M8 11V7a4 4 0 0 1 8 0v4" />
    </svg>
  ),
  bolt: (p: P) => (
    <svg {...base} {...p}>
      <path d="M13 2 4 14h7l-1 8 9-12h-7z" />
    </svg>
  ),
  terminal: (p: P) => (
    <svg {...base} {...p}>
      <rect x="3" y="4" width="18" height="16" rx="2" />
      <path d="m7 10 3 2-3 2" />
      <path d="M13 14h4" />
    </svg>
  ),
  branch: (p: P) => (
    <svg {...base} {...p}>
      <circle cx="6" cy="5" r="2" />
      <circle cx="6" cy="19" r="2" />
      <circle cx="18" cy="12" r="2" />
      <path d="M6 7v10" />
      <path d="M6 14a6 6 0 0 0 6-6h4" />
    </svg>
  ),
  doc: (p: P) => (
    <svg {...base} {...p}>
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <path d="M14 2v6h6" />
    </svg>
  ),
}
