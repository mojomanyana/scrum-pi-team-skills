export interface TrustedFixtureGitPolicyV1Definition {
  policyId: string;
  trustedParent: string;
  gitExecutable: string;
  gitExecPath: string;
  namedChecks: readonly {
    checkId: string;
    executable: string;
    argv: readonly string[];
    maxDurationMs: number;
    maxOutputBytes: number;
  }[];
  limits: Record<string, number>;
}
export type TrustedFixtureGitPolicyV1 = TrustedFixtureGitPolicyV1Definition;
const issued = new WeakSet<object>();
export function createTrustedFixtureGitPolicyV1(
  definition: TrustedFixtureGitPolicyV1Definition,
): TrustedFixtureGitPolicyV1 {
  const policy = Object.freeze({
    ...definition,
    namedChecks: Object.freeze(
      definition.namedChecks.map((c) => Object.freeze({ ...c })),
    ),
  });
  issued.add(policy);
  return policy;
}
export const isTrustedFixtureGitPolicyV1 = (
  v: unknown,
): v is TrustedFixtureGitPolicyV1 =>
  !!v && typeof v === "object" && issued.has(v as object);
