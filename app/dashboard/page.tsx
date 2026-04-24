"use client";

import { motion } from "framer-motion";
import Link from "next/link";
import {
  Shield,
  AlertTriangle,
  CheckCircle2,
  Clock,
  FolderGit2,
  GitBranch,
  ArrowRight,
  Scan,
  TrendingUp,
  TrendingDown,
  Activity,
  Calendar,
  ChevronRight,
  Plus,
  ExternalLink,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Navigation } from "@/components/navigation";
import { SecurityScore } from "@/components/security-score";
import { StatCard } from "@/components/stat-card";
import { SeverityBadge } from "@/components/severity-badge";
import { cn } from "@/lib/utils";

const recentScans = [
  {
    id: "1",
    repo: "my-awesome-app",
    branch: "main",
    score: 87,
    issues: { critical: 1, high: 2, medium: 3 },
    time: "2 hours ago",
    trend: 5,
  },
  {
    id: "2",
    repo: "next-saas-starter",
    branch: "develop",
    score: 72,
    issues: { critical: 3, high: 4, medium: 5 },
    time: "1 day ago",
    trend: -3,
  },
  {
    id: "3",
    repo: "api-gateway",
    branch: "main",
    score: 95,
    issues: { critical: 0, high: 0, medium: 2 },
    time: "3 days ago",
    trend: 12,
  },
  {
    id: "4",
    repo: "mobile-backend",
    branch: "main",
    score: 68,
    issues: { critical: 2, high: 5, medium: 8 },
    time: "1 week ago",
    trend: -8,
  },
];

const recentActivity = [
  { type: "fix", message: "SQL Injection fixed in api/users.ts", time: "10 min ago" },
  { type: "scan", message: "Scan completed for my-awesome-app", time: "2 hours ago" },
  { type: "alert", message: "New critical vulnerability detected", time: "5 hours ago" },
  { type: "fix", message: "XSS vulnerability patched", time: "1 day ago" },
  { type: "scan", message: "Scan completed for next-saas-starter", time: "1 day ago" },
];

export default function DashboardPage() {
  const overallScore = 82;
  const totalIssues = 24;
  const fixedThisWeek = 12;
  const scansThisMonth = 47;

  return (
    <div className="min-h-screen bg-background">
      <Navigation />

      <main className="container mx-auto px-4 pt-20 pb-16">
        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 mb-8">
          <div>
            <h1 className="text-2xl font-bold mb-1">Security Dashboard</h1>
            <p className="text-muted-foreground">
              Monitor and manage security across all your projects
            </p>
          </div>
          <Button asChild className="glow-primary">
            <Link href="/scan">
              <Plus className="w-4 h-4 mr-2" />
              New Scan
            </Link>
          </Button>
        </div>

        {/* Overview Stats */}
        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0 }}
          >
            <Card className="bg-card/50 backdrop-blur-sm h-full">
              <CardContent className="p-5 flex items-center gap-4">
                <SecurityScore score={overallScore} size="sm" showLabel={false} />
                <div>
                  <p className="text-sm text-muted-foreground">Overall Score</p>
                  <p className="text-2xl font-bold">{overallScore}</p>
                  <div className="flex items-center gap-1 text-xs text-success">
                    <TrendingUp className="w-3 h-3" />
                    +5 this week
                  </div>
                </div>
              </CardContent>
            </Card>
          </motion.div>

          <StatCard
            title="Open Issues"
            value={totalIssues}
            subtitle="Across all projects"
            icon={AlertTriangle}
            variant="warning"
            index={1}
          />

          <StatCard
            title="Fixed This Week"
            value={fixedThisWeek}
            subtitle="Issues resolved"
            icon={CheckCircle2}
            variant="success"
            index={2}
          />

          <StatCard
            title="Scans This Month"
            value={scansThisMonth}
            subtitle="Total scans run"
            icon={Activity}
            variant="primary"
            index={3}
          />
        </div>

        <div className="grid lg:grid-cols-3 gap-6">
          {/* Recent Scans */}
          <div className="lg:col-span-2 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold">Recent Scans</h2>
              <Button variant="ghost" size="sm" className="text-muted-foreground">
                View All
                <ChevronRight className="w-4 h-4 ml-1" />
              </Button>
            </div>

            <div className="space-y-3">
              {recentScans.map((scan, index) => (
                <motion.div
                  key={scan.id}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: index * 0.05 }}
                >
                  <Card className="bg-card/50 backdrop-blur-sm hover:border-primary/30 transition-colors">
                    <CardContent className="p-4">
                      <div className="flex items-center gap-4">
                        <SecurityScore score={scan.score} size="sm" showLabel={false} />

                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <FolderGit2 className="w-4 h-4 text-muted-foreground" />
                            <span className="font-medium truncate">{scan.repo}</span>
                          </div>
                          <div className="flex items-center gap-3 mt-1 text-sm text-muted-foreground">
                            <span className="flex items-center gap-1">
                              <GitBranch className="w-3 h-3" />
                              {scan.branch}
                            </span>
                            <span className="flex items-center gap-1">
                              <Clock className="w-3 h-3" />
                              {scan.time}
                            </span>
                          </div>
                        </div>

                        <div className="flex items-center gap-4">
                          <div className="flex items-center gap-2">
                            {scan.issues.critical > 0 && (
                              <span className="px-2 py-0.5 text-xs font-medium rounded-full bg-destructive/10 text-destructive">
                                {scan.issues.critical} critical
                              </span>
                            )}
                            {scan.issues.high > 0 && (
                              <span className="px-2 py-0.5 text-xs font-medium rounded-full bg-warning/10 text-warning">
                                {scan.issues.high} high
                              </span>
                            )}
                          </div>

                          <div className="flex items-center gap-1">
                            {scan.trend > 0 ? (
                              <TrendingUp className="w-4 h-4 text-success" />
                            ) : scan.trend < 0 ? (
                              <TrendingDown className="w-4 h-4 text-destructive" />
                            ) : null}
                            <span
                              className={cn(
                                "text-sm font-medium",
                                scan.trend > 0 ? "text-success" : scan.trend < 0 ? "text-destructive" : "text-muted-foreground"
                              )}
                            >
                              {scan.trend > 0 ? `+${scan.trend}` : scan.trend}
                            </span>
                          </div>

                          <Button variant="ghost" size="icon" asChild>
                            <Link href="/report">
                              <ArrowRight className="w-4 h-4" />
                            </Link>
                          </Button>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </motion.div>
              ))}
            </div>
          </div>

          {/* Activity Feed */}
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold">Recent Activity</h2>
              <Button variant="ghost" size="sm" className="text-muted-foreground">
                View All
              </Button>
            </div>

            <Card className="bg-card/50 backdrop-blur-sm">
              <CardContent className="p-4">
                <div className="space-y-4">
                  {recentActivity.map((activity, index) => (
                    <motion.div
                      key={index}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: index * 0.05 }}
                      className="flex items-start gap-3"
                    >
                      <div
                        className={cn(
                          "mt-0.5 p-1.5 rounded",
                          activity.type === "fix" && "bg-success/10 text-success",
                          activity.type === "scan" && "bg-primary/10 text-primary",
                          activity.type === "alert" && "bg-destructive/10 text-destructive"
                        )}
                      >
                        {activity.type === "fix" && <CheckCircle2 className="w-3 h-3" />}
                        {activity.type === "scan" && <Scan className="w-3 h-3" />}
                        {activity.type === "alert" && <AlertTriangle className="w-3 h-3" />}
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm">{activity.message}</p>
                        <p className="text-xs text-muted-foreground">{activity.time}</p>
                      </div>
                    </motion.div>
                  ))}
                </div>
              </CardContent>
            </Card>

            {/* Quick Actions */}
            <Card className="bg-card/50 backdrop-blur-sm">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium">Quick Actions</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <Button variant="outline" className="w-full justify-start gap-2" asChild>
                  <Link href="/scan">
                    <Scan className="w-4 h-4" />
                    Run New Scan
                  </Link>
                </Button>
                <Button variant="outline" className="w-full justify-start gap-2" asChild>
                  <Link href="/issues">
                    <AlertTriangle className="w-4 h-4" />
                    Review Issues
                  </Link>
                </Button>
                <Button variant="outline" className="w-full justify-start gap-2" asChild>
                  <Link href="/settings">
                    <Calendar className="w-4 h-4" />
                    Schedule Scans
                  </Link>
                </Button>
              </CardContent>
            </Card>
          </div>
        </div>
      </main>
    </div>
  );
}
