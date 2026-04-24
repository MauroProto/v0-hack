import { cn } from "@/lib/utils";

export type SeverityLevel = "critical" | "high" | "medium" | "low" | "info";

interface SeverityBadgeProps {
  severity: SeverityLevel;
  className?: string;
  showDot?: boolean;
}

const severityConfig: Record<SeverityLevel, { label: string; className: string; dotClassName: string }> = {
  critical: {
    label: "Critical",
    className: "bg-destructive/15 text-destructive border-destructive/30",
    dotClassName: "bg-destructive",
  },
  high: {
    label: "High",
    className: "bg-destructive/10 text-destructive/90 border-destructive/20",
    dotClassName: "bg-destructive/90",
  },
  medium: {
    label: "Medium",
    className: "bg-warning/15 text-warning border-warning/30",
    dotClassName: "bg-warning",
  },
  low: {
    label: "Low",
    className: "bg-info/15 text-info border-info/30",
    dotClassName: "bg-info",
  },
  info: {
    label: "Info",
    className: "bg-muted text-muted-foreground border-border",
    dotClassName: "bg-muted-foreground",
  },
};

export function SeverityBadge({ severity, className, showDot = true }: SeverityBadgeProps) {
  const config = severityConfig[severity];

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 px-2 py-0.5 text-xs font-medium rounded-full border",
        config.className,
        className
      )}
    >
      {showDot && (
        <span className={cn("w-1.5 h-1.5 rounded-full", config.dotClassName)} />
      )}
      {config.label}
    </span>
  );
}
