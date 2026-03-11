import { useState } from "react";
import { ChevronRight } from "lucide-react";
import { cn } from "@/lib/utils";

interface RawDataViewProps {
  requestJson?: string;
  responseJson?: string;
  policyApplied?: string;
}

export function RawDataView({
  requestJson,
  responseJson,
  policyApplied,
}: RawDataViewProps) {
  const [open, setOpen] = useState(false);

  const sections = [
    { label: "Request", data: requestJson },
    { label: "Response", data: responseJson },
    { label: "Policy Applied", data: policyApplied },
  ].filter((s) => s.data);

  if (sections.length === 0) return null;

  return (
    <div className="border border-border rounded overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center gap-2 w-full px-3 py-2 text-xs font-mono text-muted-foreground hover:bg-secondary/20 transition-colors"
      >
        <ChevronRight
          className={cn(
            "w-3 h-3 transition-transform",
            open && "rotate-90"
          )}
        />
        Raw Data
      </button>

      {open && (
        <div className="border-t border-border divide-y divide-border">
          {sections.map((s) => (
            <div key={s.label} className="px-3 py-2">
              <div className="text-[10px] font-mono text-muted-foreground uppercase tracking-wider mb-1">
                {s.label}
              </div>
              <pre className="font-mono text-[11px] text-foreground/70 overflow-x-auto scrollbar-thin whitespace-pre leading-relaxed">
                {s.data}
              </pre>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
