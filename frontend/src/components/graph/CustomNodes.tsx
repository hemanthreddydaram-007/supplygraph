"use client";

import React from "react";
import { Handle, Position, NodeProps, Node } from "@xyflow/react";
import { GraphNodeData } from "@/types";
import { 
  Box, 
  Server, 
  Database, 
  Globe, 
  Cloud, 
  AlertTriangle, 
  GitCommit, 
  ShieldAlert, 
  Bug 
} from "lucide-react";
import { cn } from "@/lib/utils";

const getNodeConfig = (type: string, isSuspicious: boolean, isAffected: boolean) => {
  let config = { 
    icon: Box, 
    color: "text-zinc-400", 
    border: "border-slate-800", 
    bg: "bg-slate-900/95",
    badgeBg: "bg-slate-800 border-slate-700 text-zinc-400"
  };

  switch (type) {
    case "Repository":
      config = { 
        icon: Globe, 
        color: "text-indigo-400", 
        border: "border-indigo-500/60", 
        bg: "bg-slate-900/95",
        badgeBg: "bg-indigo-500/10 border-indigo-500/30 text-indigo-300"
      };
      break;
    case "Version":
    case "Package":
      config = { 
        icon: Box, 
        color: "text-sky-400", 
        border: "border-sky-500/40", 
        bg: "bg-slate-900/95",
        badgeBg: "bg-sky-950/40 border-sky-500/30 text-sky-300"
      };
      break;
    case "Vulnerability":
      config = { 
        icon: Bug, 
        color: "text-red-400", 
        border: "border-red-500/80", 
        bg: "bg-slate-900/95",
        badgeBg: "bg-red-500/10 border-red-500/30 text-red-400"
      };
      break;
    case "Service":
      config = { 
        icon: Server, 
        color: "text-amber-400", 
        border: "border-amber-500/50", 
        bg: "bg-slate-900/95",
        badgeBg: "bg-amber-500/10 border-amber-500/30 text-amber-300"
      };
      break;
    case "API":
      config = { 
        icon: Cloud, 
        color: "text-cyan-400", 
        border: "border-cyan-500/50", 
        bg: "bg-slate-900/95",
        badgeBg: "bg-cyan-500/10 border-cyan-500/30 text-cyan-300"
      };
      break;
    case "Deployment":
      config = { 
        icon: Database, 
        color: "text-rose-400", 
        border: "border-rose-500/50", 
        bg: "bg-slate-900/95",
        badgeBg: "bg-rose-500/10 border-rose-500/30 text-rose-300"
      };
      break;
    case "Pipeline":
      config = { 
        icon: GitCommit, 
        color: "text-emerald-400", 
        border: "border-emerald-500/50", 
        bg: "bg-slate-900/95",
        badgeBg: "bg-emerald-500/10 border-emerald-500/30 text-emerald-300"
      };
      break;
  }

  if (isSuspicious) {
    config.border = "border-red-500/80";
    config.bg = "bg-slate-900/95";
    config.color = "text-red-400";
    config.badgeBg = "bg-red-500/20 border-red-500/50 text-red-300";
  } else if (isAffected) {
    config.border = "border-amber-500/60";
    config.bg = "bg-slate-900/95";
    config.color = "text-amber-400";
    config.badgeBg = "bg-amber-500/20 border-amber-500/40 text-amber-300";
  }

  return config;
};

export const BaseNode = React.memo(({ data, isConnectable }: NodeProps<Node<GraphNodeData>>) => {
  const isSuspicious = !!data.is_suspicious;
  const isAffected = !!data.is_affected;
  
  const config = getNodeConfig(data.node_type, isSuspicious, isAffected);
  const Icon = config.icon;

  return (
    <div
      style={{ willChange: "transform" }}
      className={cn(
        "group relative px-3 py-2.5 rounded-lg border min-w-[190px] max-w-[260px] transition-colors duration-150 hover:border-zinc-500",
        config.bg,
        config.border
      )}
    >
      <Handle
        type="target"
        position={Position.Left}
        isConnectable={isConnectable}
        className="w-2 h-2 bg-zinc-600 border border-zinc-900 rounded-full"
      />
      
      <div className="flex items-center space-x-2.5">
        <div className={cn("p-1.5 rounded-md flex items-center justify-center border", config.badgeBg)}>
          <Icon size={14} className={config.color} />
        </div>
        
        <div className="flex flex-col min-w-0 flex-1">
          <div className="flex items-center justify-between">
            <span className="text-[9px] font-mono uppercase tracking-wider text-zinc-400">
              {data.node_type}
            </span>
            {isSuspicious && (
              <span className="inline-flex items-center px-1.5 py-0.2 rounded text-[8px] font-semibold bg-red-500/20 text-red-400 border border-red-500/30">
                THREAT
              </span>
            )}
          </div>
          <span className="text-xs font-semibold text-zinc-100 truncate mt-0.5" title={data.label}>
            {data.label}
          </span>
        </div>
      </div>

      {(isSuspicious || (data.finding_count || 0) > 0) && (
        <div className="mt-2.5 flex items-center justify-between pt-2 border-t border-zinc-800/80">
          <div className="flex items-center space-x-1.5">
            <ShieldAlert size={12} className="text-red-400" />
            <span className="text-[10px] font-medium text-red-400">
              {data.finding_count || 0} Finding{(data.finding_count || 0) !== 1 ? 's' : ''}
            </span>
          </div>
          <span className="text-[9px] font-mono text-zinc-500">REACHABLE</span>
        </div>
      )}

      <Handle
        type="source"
        position={Position.Right}
        isConnectable={isConnectable}
        className="w-2 h-2 bg-zinc-600 border border-zinc-900 rounded-full"
      />
    </div>
  );
});

BaseNode.displayName = "BaseNode";

export const RepositoryNode = React.memo(BaseNode);
RepositoryNode.displayName = "RepositoryNode";

export const PackageNode = React.memo(BaseNode);
PackageNode.displayName = "PackageNode";

export const ServiceNode = React.memo(BaseNode);
ServiceNode.displayName = "ServiceNode";

export const ApiNode = React.memo(BaseNode);
ApiNode.displayName = "ApiNode";

export const DeploymentNode = React.memo(BaseNode);
DeploymentNode.displayName = "DeploymentNode";

export const VulnerabilityNode = React.memo(BaseNode);
VulnerabilityNode.displayName = "VulnerabilityNode";

export const nodeTypes = {
  repositoryNode: RepositoryNode,
  packageNode: PackageNode,
  serviceNode: ServiceNode,
  apiNode: ApiNode,
  deploymentNode: DeploymentNode,
  vulnerabilityNode: VulnerabilityNode,
  default: BaseNode,
};