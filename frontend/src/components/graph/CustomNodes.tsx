"use client";

import React from "react";
import { Handle, Position, NodeProps, Node } from "@xyflow/react";
import { GraphNodeData } from "@/types";
import { Box, Server, Database, Globe, Cloud, AlertTriangle, GitCommit } from "lucide-react";
import { cn } from "@/lib/utils";

// Linear-inspired dark node styling
const getNodeConfig = (type: string, isSuspicious: boolean, isAffected: boolean) => {
  let config = { icon: Box, color: "text-muted-foreground", border: "border-border/50", bg: "bg-background/80" };

  switch (type) {
    case "Repository":
      config = { icon: Globe, color: "text-indigo-400", border: "border-indigo-500/30", bg: "bg-indigo-950/20" };
      break;
    case "Version":
    case "Package":
      config = { icon: Box, color: "text-sky-400", border: "border-sky-500/30", bg: "bg-sky-950/20" };
      break;
    case "Service":
      config = { icon: Server, color: "text-orange-400", border: "border-orange-500/30", bg: "bg-orange-950/20" };
      break;
    case "API":
      config = { icon: Cloud, color: "text-amber-400", border: "border-amber-500/30", bg: "bg-amber-950/20" };
      break;
    case "Deployment":
      config = { icon: Database, color: "text-rose-400", border: "border-rose-500/30", bg: "bg-rose-950/20" };
      break;
    case "Pipeline":
      config = { icon: GitCommit, color: "text-emerald-400", border: "border-emerald-500/30", bg: "bg-emerald-950/20" };
      break;
  }

  if (isSuspicious) {
    config.border = "border-destructive shadow-[0_0_15px_rgba(220,38,38,0.3)]";
    config.bg = "bg-destructive/10";
    config.color = "text-destructive";
  } else if (isAffected) {
    config.border = "border-orange-500/50 shadow-[0_0_10px_rgba(249,115,22,0.15)]";
    config.bg = "bg-orange-500/10";
  }

  return config;
};

export const BaseNode = ({ data, isConnectable }: NodeProps<Node<GraphNodeData>>) => {
  const isSuspicious = !!data.is_suspicious;
  const isAffected = !!data.is_affected;
  
  const config = getNodeConfig(data.node_type, isSuspicious, isAffected);
  const Icon = config.icon;

  return (
    <div
      className={cn(
        "px-3 py-2 rounded-md border min-w-[180px] backdrop-blur-sm font-sans transition-colors duration-200",
        config.bg,
        config.border
      )}
    >
      <Handle
        type="target"
        position={Position.Left}
        isConnectable={isConnectable}
        className="w-2 h-2 bg-muted-foreground/50 border-0"
      />
      
      <div className="flex items-center space-x-3">
        <div className={cn("p-1.5 rounded flex items-center justify-center bg-background/50 border border-border/50", config.color)}>
          <Icon size={14} />
        </div>
        <div className="flex flex-col">
          <span className="text-[9px] font-semibold uppercase tracking-widest text-muted-foreground/80">
            {data.node_type}
          </span>
          <span className="text-xs font-medium text-foreground tracking-tight mt-0.5">
            {data.label}
          </span>
        </div>
      </div>

      {(isSuspicious || (data.finding_count || 0) > 0) && (
        <div className="mt-2 flex items-center space-x-1.5 pt-2 border-t border-border/50">
          <AlertTriangle size={10} className="text-destructive" />
          <span className="text-[10px] font-semibold text-destructive uppercase tracking-wider">
            {data.finding_count || 0} Finding{(data.finding_count || 0) !== 1 ? 's' : ''}
          </span>
        </div>
      )}

      <Handle
        type="source"
        position={Position.Right}
        isConnectable={isConnectable}
        className="w-2 h-2 bg-muted-foreground/50 border-0"
      />
    </div>
  );
};

export const nodeTypes = {
  repositoryNode: BaseNode,
  packageNode: BaseNode,
  serviceNode: BaseNode,
  apiNode: BaseNode,
  deploymentNode: BaseNode,
  default: BaseNode,
};
