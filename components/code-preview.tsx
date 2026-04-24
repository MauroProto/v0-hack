"use client";

import { motion } from "framer-motion";
import { cn } from "@/lib/utils";

interface CodeLine {
  number: number;
  content: string;
  highlight?: "error" | "warning" | "success" | "info";
  isNew?: boolean;
  isRemoved?: boolean;
}

interface CodePreviewProps {
  lines: CodeLine[];
  filename?: string;
  language?: string;
  className?: string;
}

export function CodePreview({ lines, filename, language = "typescript", className }: CodePreviewProps) {
  return (
    <div className={cn("rounded-lg border border-border overflow-hidden bg-card", className)}>
      {/* Header */}
      {filename && (
        <div className="flex items-center gap-2 px-4 py-2 bg-secondary/50 border-b border-border">
          <div className="flex gap-1.5">
            <span className="w-3 h-3 rounded-full bg-destructive/60" />
            <span className="w-3 h-3 rounded-full bg-warning/60" />
            <span className="w-3 h-3 rounded-full bg-success/60" />
          </div>
          <span className="text-xs text-muted-foreground font-mono ml-2">{filename}</span>
          <span className="text-xs text-muted-foreground/60 ml-auto">{language}</span>
        </div>
      )}
      
      {/* Code content */}
      <div className="overflow-x-auto">
        <pre className="text-sm font-mono">
          {lines.map((line, index) => (
            <motion.div
              key={line.number}
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.2, delay: index * 0.02 }}
              className={cn(
                "flex",
                line.highlight === "error" && "bg-destructive/10",
                line.highlight === "warning" && "bg-warning/10",
                line.highlight === "success" && "bg-success/10",
                line.highlight === "info" && "bg-info/10",
                line.isNew && "bg-success/10",
                line.isRemoved && "bg-destructive/10 line-through opacity-60"
              )}
            >
              {/* Line number */}
              <span
                className={cn(
                  "flex-shrink-0 w-12 px-3 py-0.5 text-right text-muted-foreground/50 select-none border-r border-border",
                  line.highlight && "text-muted-foreground"
                )}
              >
                {line.number}
              </span>
              
              {/* Diff indicator */}
              <span className="w-6 flex-shrink-0 text-center py-0.5">
                {line.isNew && <span className="text-success">+</span>}
                {line.isRemoved && <span className="text-destructive">-</span>}
              </span>
              
              {/* Code content */}
              <code
                className={cn(
                  "flex-1 px-2 py-0.5 text-foreground whitespace-pre",
                  line.highlight === "error" && "text-destructive",
                  line.highlight === "warning" && "text-warning",
                  line.highlight === "success" && "text-success"
                )}
              >
                {line.content}
              </code>
            </motion.div>
          ))}
        </pre>
      </div>
    </div>
  );
}
