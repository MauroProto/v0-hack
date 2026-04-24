"use client";

import { motion } from "framer-motion";
import Link from "next/link";
import {
  Shield,
  Zap,
  Eye,
  Sparkles,
  Code2,
  Lock,
  CheckCircle2,
  ArrowRight,
  Github,
  GitBranch,
  Terminal,
  FileCode,
  AlertTriangle,
  Bot,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Navigation } from "@/components/navigation";
import { ShieldLogo } from "@/components/shield-logo";
import { SecurityScore } from "@/components/security-score";

const features = [
  {
    icon: Eye,
    title: "Deep Code Analysis",
    description: "AI-powered scanning that understands context, not just patterns. Catches vulnerabilities other tools miss.",
  },
  {
    icon: Sparkles,
    title: "Auto-Fix Suggestions",
    description: "Get intelligent fix suggestions with one-click application. Powered by LLMs trained on security best practices.",
  },
  {
    icon: Zap,
    title: "Real-time Scanning",
    description: "Scan on every commit or in real-time as you code. Instant feedback keeps your code secure from day one.",
  },
  {
    icon: Lock,
    title: "Vibe-Code Aware",
    description: "Specifically trained on AI-generated code patterns. Understands the unique vulnerabilities of vibe coding.",
  },
];

const stats = [
  { value: "50K+", label: "Scans Completed" },
  { value: "2M+", label: "Issues Detected" },
  { value: "99.7%", label: "Accuracy Rate" },
  { value: "<2s", label: "Average Scan Time" },
];

const steps = [
  {
    icon: Github,
    title: "Connect Your Repo",
    description: "Link your GitHub, GitLab, or paste a URL. We support all major platforms.",
  },
  {
    icon: Terminal,
    title: "Run the Scan",
    description: "Our AI analyzes your code for 200+ vulnerability patterns in seconds.",
  },
  {
    icon: FileCode,
    title: "Review & Fix",
    description: "Get detailed reports with auto-fix suggestions you can apply instantly.",
  },
];

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-background">
      <Navigation variant="landing" />

      {/* Hero Section */}
      <section className="relative pt-32 pb-20 overflow-hidden">
        {/* Background effects */}
        <div className="absolute inset-0 grid-pattern opacity-30" />
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-primary/10 rounded-full blur-3xl" />
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-primary/5 rounded-full blur-3xl" />

        <div className="container mx-auto px-4 relative">
          <div className="max-w-4xl mx-auto text-center space-y-8">
            {/* Badge */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5 }}
              className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full border border-primary/30 bg-primary/5 text-sm"
            >
              <Sparkles className="w-4 h-4 text-primary" />
              <span className="text-primary font-medium">AI-Powered Security for the Vibe Coding Era</span>
            </motion.div>

            {/* Heading */}
            <motion.h1
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.1 }}
              className="text-4xl sm:text-5xl md:text-6xl font-bold tracking-tight text-balance"
            >
              Ship Fast.{" "}
              <span className="gradient-text">Stay Secure.</span>
            </motion.h1>

            {/* Subheading */}
            <motion.p
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.2 }}
              className="text-lg sm:text-xl text-muted-foreground max-w-2xl mx-auto text-pretty"
            >
              VibeShield scans your AI-generated code for security vulnerabilities, 
              giving you the confidence to ship at the speed of thought.
            </motion.p>

            {/* CTA Buttons */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.3 }}
              className="flex flex-col sm:flex-row items-center justify-center gap-4"
            >
              <Button size="lg" asChild className="glow-primary text-base px-8">
                <Link href="/scan">
                  Start Free Scan
                  <ArrowRight className="w-4 h-4 ml-2" />
                </Link>
              </Button>
              <Button variant="outline" size="lg" asChild className="text-base">
                <Link href="/dashboard">
                  View Demo Dashboard
                </Link>
              </Button>
            </motion.div>

            {/* Hero Visual */}
            <motion.div
              initial={{ opacity: 0, y: 40 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.7, delay: 0.4 }}
              className="pt-12"
            >
              <div className="relative max-w-3xl mx-auto">
                {/* Mock terminal/dashboard preview */}
                <div className="rounded-xl border border-border bg-card/80 backdrop-blur-sm shadow-2xl shadow-primary/5 overflow-hidden">
                  {/* Terminal header */}
                  <div className="flex items-center gap-2 px-4 py-3 bg-secondary/50 border-b border-border">
                    <div className="flex gap-1.5">
                      <span className="w-3 h-3 rounded-full bg-destructive/60" />
                      <span className="w-3 h-3 rounded-full bg-warning/60" />
                      <span className="w-3 h-3 rounded-full bg-success/60" />
                    </div>
                    <span className="text-xs text-muted-foreground font-mono ml-2">
                      vibeshield scan ./my-app
                    </span>
                  </div>

                  {/* Terminal content */}
                  <div className="p-6 space-y-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-4">
                        <ShieldLogo size="lg" />
                        <div>
                          <h3 className="font-semibold text-lg">Security Report</h3>
                          <p className="text-sm text-muted-foreground">my-awesome-app</p>
                        </div>
                      </div>
                      <SecurityScore score={87} size="md" />
                    </div>

                    <div className="grid grid-cols-3 gap-4 pt-4">
                      <div className="p-3 rounded-lg bg-destructive/10 border border-destructive/20">
                        <p className="text-2xl font-bold text-destructive">3</p>
                        <p className="text-xs text-muted-foreground">Critical</p>
                      </div>
                      <div className="p-3 rounded-lg bg-warning/10 border border-warning/20">
                        <p className="text-2xl font-bold text-warning">7</p>
                        <p className="text-xs text-muted-foreground">Medium</p>
                      </div>
                      <div className="p-3 rounded-lg bg-info/10 border border-info/20">
                        <p className="text-2xl font-bold text-info">12</p>
                        <p className="text-xs text-muted-foreground">Low</p>
                      </div>
                    </div>

                    <div className="space-y-2 pt-2">
                      {[
                        { severity: "critical", text: "SQL Injection in auth/login.ts:45" },
                        { severity: "warning", text: "Missing rate limiting in api/users.ts" },
                        { severity: "info", text: "Outdated dependency: lodash@4.17.15" },
                      ].map((item, i) => (
                        <motion.div
                          key={i}
                          initial={{ opacity: 0, x: -20 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ delay: 0.6 + i * 0.1 }}
                          className="flex items-center gap-3 p-2 rounded-lg bg-secondary/50"
                        >
                          <AlertTriangle
                            className={`w-4 h-4 ${
                              item.severity === "critical"
                                ? "text-destructive"
                                : item.severity === "warning"
                                ? "text-warning"
                                : "text-info"
                            }`}
                          />
                          <span className="text-sm font-mono text-muted-foreground">{item.text}</span>
                          <Button variant="ghost" size="sm" className="ml-auto h-6 text-xs text-primary">
                            Auto-fix
                          </Button>
                        </motion.div>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Decorative elements */}
                <div className="absolute -top-4 -right-4 w-24 h-24 bg-primary/20 rounded-full blur-2xl" />
                <div className="absolute -bottom-4 -left-4 w-32 h-32 bg-primary/10 rounded-full blur-2xl" />
              </div>
            </motion.div>
          </div>
        </div>
      </section>

      {/* Stats Section */}
      <section className="py-16 border-y border-border bg-secondary/20">
        <div className="container mx-auto px-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
            {stats.map((stat, i) => (
              <motion.div
                key={stat.label}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.5, delay: i * 0.1 }}
                className="text-center"
              >
                <p className="text-3xl md:text-4xl font-bold gradient-text">{stat.value}</p>
                <p className="text-sm text-muted-foreground mt-1">{stat.label}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section id="features" className="py-24">
        <div className="container mx-auto px-4">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="text-center max-w-2xl mx-auto mb-16"
          >
            <h2 className="text-3xl md:text-4xl font-bold mb-4">
              Security That Keeps Up With Your Vibe
            </h2>
            <p className="text-muted-foreground text-lg">
              Built for the new generation of developers who build fast with AI assistance.
            </p>
          </motion.div>

          <div className="grid md:grid-cols-2 gap-6 max-w-4xl mx-auto">
            {features.map((feature, i) => (
              <motion.div
                key={feature.title}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.5, delay: i * 0.1 }}
              >
                <Card className="h-full bg-card/50 backdrop-blur-sm border-border/50 hover:border-primary/30 transition-colors">
                  <CardContent className="p-6">
                    <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center mb-4">
                      <feature.icon className="w-6 h-6 text-primary" />
                    </div>
                    <h3 className="text-lg font-semibold mb-2">{feature.title}</h3>
                    <p className="text-muted-foreground text-sm">{feature.description}</p>
                  </CardContent>
                </Card>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* How it Works Section */}
      <section id="how-it-works" className="py-24 bg-secondary/20">
        <div className="container mx-auto px-4">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="text-center max-w-2xl mx-auto mb-16"
          >
            <h2 className="text-3xl md:text-4xl font-bold mb-4">
              How It Works
            </h2>
            <p className="text-muted-foreground text-lg">
              From code to secure in three simple steps.
            </p>
          </motion.div>

          <div className="grid md:grid-cols-3 gap-8 max-w-4xl mx-auto">
            {steps.map((step, i) => (
              <motion.div
                key={step.title}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.5, delay: i * 0.1 }}
                className="text-center"
              >
                <div className="relative inline-flex mb-6">
                  <div className="w-16 h-16 rounded-2xl bg-primary/10 flex items-center justify-center">
                    <step.icon className="w-8 h-8 text-primary" />
                  </div>
                  <span className="absolute -top-2 -right-2 w-6 h-6 rounded-full bg-primary text-primary-foreground text-sm font-bold flex items-center justify-center">
                    {i + 1}
                  </span>
                </div>
                <h3 className="text-lg font-semibold mb-2">{step.title}</h3>
                <p className="text-muted-foreground text-sm">{step.description}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-24">
        <div className="container mx-auto px-4">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="max-w-3xl mx-auto text-center"
          >
            <div className="inline-flex mb-8">
              <ShieldLogo size="lg" />
            </div>
            <h2 className="text-3xl md:text-4xl font-bold mb-4">
              Ready to Secure Your Vibe-Coded Apps?
            </h2>
            <p className="text-muted-foreground text-lg mb-8">
              Start your first scan for free. No credit card required.
            </p>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
              <Button size="lg" asChild className="glow-primary text-base px-8">
                <Link href="/scan">
                  Start Free Scan
                  <ArrowRight className="w-4 h-4 ml-2" />
                </Link>
              </Button>
              <Button variant="ghost" size="lg" className="text-muted-foreground">
                <Bot className="w-4 h-4 mr-2" />
                Talk to Sales
              </Button>
            </div>
          </motion.div>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-12 border-t border-border">
        <div className="container mx-auto px-4">
          <div className="flex flex-col md:flex-row items-center justify-between gap-6">
            <div className="flex items-center gap-2">
              <ShieldLogo size="sm" animate={false} />
              <span className="font-semibold">VibeShield</span>
            </div>
            <p className="text-sm text-muted-foreground">
              Made with security in mind. Ship fast, stay safe.
            </p>
            <div className="flex items-center gap-6">
              <Link href="#" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                Privacy
              </Link>
              <Link href="#" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                Terms
              </Link>
              <Link href="#" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                Docs
              </Link>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
