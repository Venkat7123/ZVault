export const BRANCHES: Record<string, string> = {
  CHN01: "Chennai",
  MUM01: "Mumbai",
  TNV01: "Tirunelveli",
};

export function branchLabel(code: string | null): string {
  if (!code) return "All branches";
  return BRANCHES[code] ? `${BRANCHES[code]} (${code})` : code;
}

/** Demo employees. Real banks do not list users; this list exists only for the demo. */
export const DEMO_EMPLOYEES = [
  { id: "CLERK1", label: "CLERK1: Clerk, Chennai" },
  { id: "CLERK2", label: "CLERK2: Clerk, Mumbai" },
  { id: "MANAGER1", label: "MANAGER1: Manager, Chennai" },
  { id: "AUDITOR1", label: "AUDITOR1: Auditor (expected to be refused)" },
] as const;
