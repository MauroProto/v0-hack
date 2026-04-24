"use client";

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { useRouter } from "next/navigation";
import {
  Github,
  GitBranch,
  Upload,
  Link as LinkIcon,
  ArrowRight,
  FolderGit2,
  Loader2,
  CheckCircle2,
  AlertCircle,
  FileCode,
  Folder,
  ChevronRight,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Navigation } from "@/components/navigation";
import { ShieldLogo } from "@/components/shield-logo";
import { ScanProgress } from "@/components/scan-progress";
import { cn } from "@/lib/utils";

type ScanMethod = "github" | "url" | "upload";
type ScanPhase = "input" | "connecting" | "scanning" | "complete";

const scanPhases = [
  { id: "parsing", label: "Parsing codebase", duration: 1500 },
  { id: "analyzing", label: "Analyzing dependencies", duration: 2000 },
  { id: "patterns", label: "Checking vulnerability patterns", duration: 2500 },
  { id: "ai", label: "Running AI security analysis", duration: 3000 },
  { id: "generating", label: "Generating report", duration: 1000 },
];

export default function ScanPage() {
  const router = useRouter();
  const [method, setMethod] = useState<ScanMethod>("github");
  const [repoUrl, setRepoUrl] = useState("");
  const [phase, setPhase] = useState<ScanPhase>("input");
  const [progress, setProgress] = useState(0);
  const [currentPhaseIndex, setCurrentPhaseIndex] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async () => {
    if (!repoUrl.trim()) {
      setError("Please enter a repository URL");
      return;
    }

    setError(null);
    setPhase("connecting");

    // Simulate connection
    await new Promise((r) => setTimeout(r, 1500));
    setPhase("scanning");

    // Simulate scanning phases
    let currentProgress = 0;
    const progressPerPhase = 100 / scanPhases.length;

    for (let i = 0; i < scanPhases.length; i++) {
      setCurrentPhaseIndex(i);
      const targetProgress = (i + 1) * progressPerPhase;

      const steps = 20;
      const stepDuration = scanPhases[i].duration / steps;

      for (let step = 0; step < steps; step++) {
        await new Promise((r) => setTimeout(r, stepDuration));
        currentProgress = currentProgress + progressPerPhase / steps;
        setProgress(Math.min(currentProgress, 100));
      }
    }

    setPhase("complete");
    await new Promise((r) => setTimeout(r, 1000));
    router.push("/report");
  };

  const methodOptions = [
    {
      id: "github" as const,
      icon: Github,
      label: "GitHub Repository",
      description: "Connect directly to your GitHub repo",
    },
    {
      id: "url" as const,
      icon: LinkIcon,
      label: "Git URL",
      description: "Any public Git repository URL",
    },
    {
      id: "upload" as const,
      icon: Upload,
      label: "Upload Code",
      description: "Upload a ZIP file of your project",
    },
  ];

  return (
    <div className="min-h-screen bg-background">
      <Navigation />

      <main className="container mx-auto px-4 pt-24 pb-16">
        <div className="max-w-2xl mx-auto">
          {/* Header */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="text-center mb-12"
          >
            <div className="inline-flex mb-6">
              <ShieldLogo size="lg" animate={phase === "scanning"} />
            </div>
            <h1 className="text-3xl font-bold mb-3">
              {phase === "input" && "Start a Security Scan"}
              {phase === "connecting" && "Connecting..."}
              {phase === "scanning" && "Scanning Your Code"}
              {phase === "complete" && "Scan Complete!"}
            </h1>
            <p className="text-muted-foreground">
              {phase === "input" && "Connect your repository to begin the security analysis"}
              {phase === "connecting" && "Establishing connection to your repository"}
              {phase === "scanning" && "Our AI is analyzing your codebase for vulnerabilities"}
              {phase === "complete" && "Your security report is ready"}
            </p>
          </motion.div>

          <AnimatePresence mode="wait">
            {/* Input Phase */}
            {phase === "input" && (
              <motion.div
                key="input"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                className="space-y-6"
              >
                {/* Method Selection */}
                <div className="grid grid-cols-3 gap-3">
                  {methodOptions.map((option) => (
                    <button
                      key={option.id}
                      onClick={() => setMethod(option.id)}
                      className={cn(
                        "p-4 rounded-lg border text-left transition-all",
                        method === option.id
                          ? "border-primary bg-primary/5"
                          : "border-border hover:border-primary/30 hover:bg-secondary/50"
                      )}
                    >
                      <option.icon
                        className={cn(
                          "w-5 h-5 mb-2",
                          method === option.id ? "text-primary" : "text-muted-foreground"
                        )}
                      />
                      <p className="font-medium text-sm">{option.label}</p>
                      <p className="text-xs text-muted-foreground mt-0.5">{option.description}</p>
                    </button>
                  ))}
                </div>

                {/* Input Form */}
                <Card className="bg-card/50 backdrop-blur-sm">
                  <CardContent className="p-6 space-y-4">
                    {method === "github" && (
                      <>
                        <div className="space-y-2">
                          <label className="text-sm font-medium">Repository URL</label>
                          <div className="relative">
                            <Github className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                            <Input
                              placeholder="https://github.com/username/repo"
                              value={repoUrl}
                              onChange={(e) => setRepoUrl(e.target.value)}
                              className="pl-10"
                            />
                          </div>
                        </div>

                        <div className="flex items-center gap-3 p-3 rounded-lg bg-secondary/50">
                          <GitBranch className="w-4 h-4 text-muted-foreground" />
                          <span className="text-sm text-muted-foreground">Branch:</span>
                          <span className="text-sm font-mono">main</span>
                        </div>

                        {/* Recent repos mock */}
                        <div className="space-y-2">
                          <p className="text-xs text-muted-foreground uppercase tracking-wider">Recent Repositories</p>
                          {[
                            { name: "my-awesome-app", time: "2 hours ago" },
                            { name: "next-saas-starter", time: "1 day ago" },
                            { name: "api-gateway", time: "3 days ago" },
                          ].map((repo) => (
                            <button
                              key={repo.name}
                              onClick={() => setRepoUrl(`https://github.com/user/${repo.name}`)}
                              className="w-full flex items-center gap-3 p-2 rounded-lg hover:bg-secondary/50 transition-colors text-left"
                            >
                              <FolderGit2 className="w-4 h-4 text-muted-foreground" />
                              <span className="text-sm font-mono flex-1">{repo.name}</span>
                              <span className="text-xs text-muted-foreground">{repo.time}</span>
                              <ChevronRight className="w-4 h-4 text-muted-foreground" />
                            </button>
                          ))}
                        </div>
                      </>
                    )}

                    {method === "url" && (
                      <div className="space-y-2">
                        <label className="text-sm font-medium">Git Clone URL</label>
                        <div className="relative">
                          <LinkIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                          <Input
                            placeholder="https://github.com/username/repo.git"
                            value={repoUrl}
                            onChange={(e) => setRepoUrl(e.target.value)}
                            className="pl-10"
                          />
                        </div>
                        <p className="text-xs text-muted-foreground">
                          Works with GitHub, GitLab, Bitbucket, and any public Git URL
                        </p>
                      </div>
                    )}

                    {method === "upload" && (
                      <div className="space-y-4">
                        <div className="border-2 border-dashed border-border rounded-lg p-8 text-center hover:border-primary/30 transition-colors cursor-pointer">
                          <Upload className="w-8 h-8 text-muted-foreground mx-auto mb-3" />
                          <p className="text-sm font-medium">Drop your ZIP file here</p>
                          <p className="text-xs text-muted-foreground mt-1">or click to browse</p>
                        </div>
                        <p className="text-xs text-muted-foreground text-center">
                          Maximum file size: 100MB
                        </p>
                      </div>
                    )}

                    {error && (
                      <div className="flex items-center gap-2 p-3 rounded-lg bg-destructive/10 text-destructive text-sm">
                        <AlertCircle className="w-4 h-4" />
                        {error}
                      </div>
                    )}
                  </CardContent>
                </Card>

                <Button
                  size="lg"
                  className="w-full glow-primary"
                  onClick={handleScan}
                  disabled={method === "upload"}
                >
                  Start Security Scan
                  <ArrowRight className="w-4 h-4 ml-2" />
                </Button>
              </motion.div>
            )}

            {/* Connecting Phase */}
            {phase === "connecting" && (
              <motion.div
                key="connecting"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                className="text-center py-12"
              >
                <Loader2 className="w-12 h-12 text-primary mx-auto mb-4 animate-spin" />
                <p className="text-muted-foreground">Cloning repository...</p>
              </motion.div>
            )}

            {/* Scanning Phase */}
            {phase === "scanning" && (
              <motion.div
                key="scanning"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
              >
                <Card className="bg-card/50 backdrop-blur-sm">
                  <CardContent className="p-6 space-y-6">
                    <ScanProgress
                      progress={progress}
                      status={scanPhases[currentPhaseIndex]?.label || "Processing..."}
                      phase="Analyzing codebase"
                    />

                    {/* Phase checklist */}
                    <div className="space-y-2">
                      {scanPhases.map((p, i) => (
                        <div
                          key={p.id}
                          className={cn(
                            "flex items-center gap-3 p-2 rounded-lg transition-colors",
                            i < currentPhaseIndex && "text-success",
                            i === currentPhaseIndex && "bg-primary/5 text-primary",
                            i > currentPhaseIndex && "text-muted-foreground"
                          )}
                        >
                          {i < currentPhaseIndex ? (
                            <CheckCircle2 className="w-4 h-4" />
                          ) : i === currentPhaseIndex ? (
                            <Loader2 className="w-4 h-4 animate-spin" />
                          ) : (
                            <div className="w-4 h-4 rounded-full border-2 border-current" />
                          )}
                          <span className="text-sm">{p.label}</span>
                        </div>
                      ))}
                    </div>

                    {/* Files being scanned */}
                    <div className="space-y-2">
                      <p className="text-xs text-muted-foreground uppercase tracking-wider">Files analyzed</p>
                      <div className="space-y-1 max-h-32 overflow-y-auto">
                        {[
                          "src/app/page.tsx",
                          "src/lib/auth.ts",
                          "src/api/users/route.ts",
                          "src/components/LoginForm.tsx",
                          "src/utils/database.ts",
                        ].map((file, i) => (
                          <motion.div
                            key={file}
                            initial={{ opacity: 0, x: -10 }}
                            animate={{ opacity: 1, x: 0 }}
                            transition={{ delay: i * 0.1 }}
                            className="flex items-center gap-2 text-xs text-muted-foreground font-mono"
                          >
                            <FileCode className="w-3 h-3" />
                            {file}
                          </motion.div>
                        ))}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </motion.div>
            )}

            {/* Complete Phase */}
            {phase === "complete" && (
              <motion.div
                key="complete"
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                className="text-center py-12"
              >
                <motion.div
                  initial={{ scale: 0 }}
                  animate={{ scale: 1 }}
                  transition={{ type: "spring", bounce: 0.5 }}
                >
                  <CheckCircle2 className="w-16 h-16 text-success mx-auto mb-4" />
                </motion.div>
                <p className="text-lg font-medium mb-2">Analysis Complete</p>
                <p className="text-muted-foreground mb-6">Redirecting to your security report...</p>
                <Loader2 className="w-5 h-5 text-primary mx-auto animate-spin" />
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </main>
    </div>
  );
}
