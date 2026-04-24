"use client";

import { motion } from "framer-motion";
import { cn } from "@/lib/utils";

interface SecurityScoreProps {
  score: number;
  size?: "sm" | "md" | "lg";
  showLabel?: boolean;
  className?: string;
}

function getScoreColor(score: number) {
  if (score >= 90) return { stroke: "oklch(0.75 0.18 165)", label: "Excellent", textClass: "text-primary" };
  if (score >= 70) return { stroke: "oklch(0.7 0.15 180)", label: "Good", textClass: "text-primary/80" };
  if (score >= 50) return { stroke: "oklch(0.8 0.18 75)", label: "Fair", textClass: "text-warning" };
  if (score >= 30) return { stroke: "oklch(0.7 0.2 40)", label: "Poor", textClass: "text-warning" };
  return { stroke: "oklch(0.6 0.22 25)", label: "Critical", textClass: "text-destructive" };
}

export function SecurityScore({ score, size = "md", showLabel = true, className }: SecurityScoreProps) {
  const { stroke, label, textClass } = getScoreColor(score);
  
  const sizeConfig = {
    sm: { dimension: 80, strokeWidth: 6, fontSize: "text-xl", labelSize: "text-[10px]" },
    md: { dimension: 120, strokeWidth: 8, fontSize: "text-3xl", labelSize: "text-xs" },
    lg: { dimension: 180, strokeWidth: 10, fontSize: "text-5xl", labelSize: "text-sm" },
  };
  
  const config = sizeConfig[size];
  const radius = (config.dimension - config.strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  return (
    <div className={cn("relative inline-flex items-center justify-center", className)}>
      <svg
        width={config.dimension}
        height={config.dimension}
        className="transform -rotate-90"
      >
        {/* Background circle */}
        <circle
          cx={config.dimension / 2}
          cy={config.dimension / 2}
          r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth={config.strokeWidth}
          className="text-secondary"
        />
        
        {/* Progress circle */}
        <motion.circle
          cx={config.dimension / 2}
          cy={config.dimension / 2}
          r={radius}
          fill="none"
          stroke={stroke}
          strokeWidth={config.strokeWidth}
          strokeLinecap="round"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: offset }}
          transition={{ duration: 1.5, ease: "easeOut" }}
          style={{ filter: "drop-shadow(0 0 8px " + stroke + ")" }}
        />
      </svg>
      
      {/* Center content */}
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <motion.span
          className={cn("font-bold font-mono", config.fontSize, textClass)}
          initial={{ opacity: 0, scale: 0.5 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.5, delay: 0.5 }}
        >
          {score}
        </motion.span>
        {showLabel && (
          <motion.span
            className={cn("text-muted-foreground uppercase tracking-wider", config.labelSize)}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.5, delay: 0.7 }}
          >
            {label}
          </motion.span>
        )}
      </div>
    </div>
  );
}
