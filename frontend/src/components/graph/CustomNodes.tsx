"use client";

import React from "react";
import { Handle, Position, NodeProps } from "@xyflow/react";
import { GraphNodeData } from "@/types";
import { Box, Server, Database, Globe, Cloud, AlertTriangle, GitCommit, User } from "lucide-react";
import { cn } from "@/lib/utils";

// Custom node styling and icon mapping based on node_type
const getNodeConfig = (type: string, isSuspicious: boolean, isAffected: boolean) => {
  let config = { icon: Box, color: "text-blue-500", border: "border-blue-200", bg: "bg-blue-50" };

  switch (type) {
    case "Repository":
      config = { icon: Globe, color: "text-indigo-500", border: "border-indigo-200", bg: "bg-indigo-50" };
      break;
    case "Version":
    case "Package":
      config = { icon: Box, color: "text-sky-500", border: "border-sky-200", bg: "bg-sky-50" };
      break;
    case "Service":
      config = { icon: Server, color: "text-orange-500", border: "border-orange-200", bg: "bg-orange-50" };
      break;
    case "API":
      config = { icon: Cloud, color: "text-amber-500", border: "border-amber-200", bg: "bg-amber-50" };
      break;
    case "Deployment":
      config = { icon: Database, color: "text-red-500", border: "border-red-200", bg: "bg-red-50" };
      break;
  }

  if (isSuspicious) {
    config.border = "border-red-500 shadow-md shadow-red-200";
    config.bg = "bg-red-50";
    config.color = "text-red-600";
  } else if (isAffected) {
    config.border = "border-orange-400";
    config.bg = "bg-orange-50";
  }

  return config;
};

export const BaseNode = ({ data, isConnectable }: NodeProps<GraphNodeData>) => {
  const isSuspicious = !!data.is_suspicious;
  const isAffected = !!data.is_affected;
  
  const config = getNodeConfig(data.node_type, isSuspicious, isAffected);
  const Icon = config.icon;

  return (
    <div
      className={cn(
        "px-4 py-3 rounded-lg border-2 min-w-[200px] bg-white font-sans",
        config.border
      )}
    >
      <Handle
        type="target"
        position={Position.Left}
        isConnectable={isConnectable}
        className="w-3 h-3 bg-slate-400"
      />
      
      <div className="flex items-center space-x-3">
        <div className={cn("p-2 rounded-md", config.bg, config.color)}>
          <Icon size={18} />
        </div>
        <div className="flex flex-col">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">
            {data.node_type}
          </span>
          <span className="text-sm font-medium text-slate-900 leading-tight mt-0.5">
            {data.label}
          </span>
        </div>
      </div>

      {(isSuspicious || data.finding_count) && (
        <div className="mt-3 flex items-center space-x-2 pt-2 border-t border-slate-100">
          <AlertTriangle size={14} className="text-red-500" />
          <span className="text-xs font-medium text-red-600">
            {data.finding_count} Finding{data.finding_count !== 1 ? 's' : ''}
          </span>
        </div>
      )}

      <Handle
        type="source"
        position={Position.Right}
        isConnectable={isConnectable}
        className="w-3 h-3 bg-slate-400"
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
