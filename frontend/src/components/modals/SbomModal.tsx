"use client";

import React from "react";
import { Check, Copy, Download, FileCode2 } from "lucide-react";
import { AnalysisResponse } from "@/types";
import { Modal } from "@/components/common/Modal";

interface SbomModalProps {
  open: boolean;
  onClose: () => void;
  data: AnalysisResponse | null;
  computedSbomSha: string;
  copiedIndex: number | string | null;
  onCopy: (text: string, key: number | string) => void;
  onDownloadSbom: () => void;
}

export function SbomModal({
  open,
  onClose,
  data,
  computedSbomSha,
  copiedIndex,
  onCopy,
  onDownloadSbom,
}: SbomModalProps) {
  const sha = data?.detector_breakdown?.sbom_sha256 || computedSbomSha || "0x9f83b2...a41e";
  const components = data?.sbom?.components || data?.components || [];

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={
        <div className="flex items-center space-x-2">
          <FileCode2 className="w-4 h-4 text-blue-400" aria-hidden="true" />
          <span>CycloneDX v1.5 Software Bill of Materials (SBOM)</span>
        </div>
      }
    >
      <div className="space-y-4">
        <div className="p-3 rounded-xl bg-zinc-900 border border-zinc-800 text-xs font-mono space-y-1.5">
          <div className="flex items-center justify-between text-zinc-400">
            <span>Standard Format:</span>
            <span className="text-zinc-200">CycloneDX v1.5 JSON</span>
          </div>
          <div className="flex items-center justify-between text-zinc-400">
            <span>Total Components:</span>
            <span className="text-zinc-200">{components.length}</span>
          </div>
          <div className="flex items-center justify-between text-zinc-400">
            <span>Deterministic SHA-256:</span>
            <div className="flex items-center space-x-2">
              <span className="text-blue-400 text-[10px] break-all font-mono">{sha}</span>
              <button
                type="button"
                onClick={() => onCopy(data?.detector_breakdown?.sbom_sha256 || computedSbomSha || "", "sbom-sha-copy")}
                aria-label="Copy SHA-256 Hash to clipboard"
                className="p-1 rounded bg-zinc-800 hover:bg-zinc-750 text-zinc-300 hover:text-white transition-colors"
                title="Copy SHA-256 Hash to clipboard"
              >
                {copiedIndex === "sbom-sha-copy" ? (
                  <Check className="w-3 h-3 text-emerald-400" aria-hidden="true" />
                ) : (
                  <Copy className="w-3 h-3 text-zinc-400" aria-hidden="true" />
                )}
              </button>
            </div>
          </div>
        </div>

        <div
          className="max-h-60 overflow-y-auto rounded-xl border border-zinc-800 bg-black/60 p-3 text-[10px] font-mono text-zinc-400 space-y-1"
          role="region"
          aria-label="SBOM Components List"
        >
          {components.map((comp: any, idx: number) => (
            <div key={idx} className="flex items-center justify-between py-0.5 border-b border-zinc-900">
              <span className="text-zinc-300 font-semibold">{comp.name}</span>
              <span className="text-zinc-500">{comp.version || "latest"}</span>
              <span className="text-zinc-500 text-[9px]">{comp.ecosystem}</span>
            </div>
          ))}
        </div>

        <div className="flex items-center justify-end space-x-2 pt-2">
          <button
            type="button"
            onClick={onDownloadSbom}
            className="px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold flex items-center space-x-1.5 transition-colors shadow-md shadow-blue-600/20"
          >
            <Download className="w-3.5 h-3.5" aria-hidden="true" />
            <span>Download CycloneDX JSON</span>
          </button>
        </div>
      </div>
    </Modal>
  );
}
