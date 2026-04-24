"use client";

import { motion } from "framer-motion";
import { cn } from "@/lib/utils";

interface ScanProgressProps {
  progress: number;
  status: string;
  phase?: string;
  className?: string;
}

export function ScanProgress({ progress, status, phase, className }: ScanProgressProps) {
  return (
    <div className={cn("space-y-3", className)}>
      <div className="flex items-center justify-between text-sm">
        <span className="text-muted-foreground">{phase || "Scanning..."}</span>
        <span className="font-mono text-primary">{Math.round(progress)}%</span>
      </div>
      
      <div className="relative h-2 bg-secondary rounded-full overflow-hidden">
        {/* Background scan line effect */}
        <div className="absolute inset-0 overflow-hidden">
          <motion.div
            className="absolute inset-y-0 w-20 bg-gradient-to-r from-transparent via-primary/20 to-transparent"
            animate={{ x: ["-100%", "500%"] }}
            transition={{ duration: 1.5, repeat: Infinity, ease: "linear" }}
          />
        </div>
        
        {/* Progress bar */}
        <motion.div
          className="absolute inset-y-0 left-0 bg-gradient-to-r from-primary to-primary/80 rounded-full"
          initial={{ width: 0 }}
          animate={{ width: `${progress}%` }}
          transition={{ duration: 0.3, ease: "easeOut" }}
        />
        
        {/* Glow effect at the end */}
        <motion.div
          className="absolute inset-y-0 w-4 bg-primary rounded-full blur-sm"
          style={{ left: `calc(${progress}% - 8px)` }}
          animate={{ opacity: [0.5, 1, 0.5] }}
          transition={{ duration: 1, repeat: Infinity }}
        />
      </div>
      
      <p className="text-xs text-muted-foreground truncate">{status}</p>
    </div>
  );
}
