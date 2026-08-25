const CREDENTIAL_ASSIGNMENT =
  /(?:^|[^A-Za-z0-9_])(?:[A-Za-z0-9]+_)*(?:password|passwd|token|api[_-]?key|bearer|secret(?:[_-]access[_-]key)?)(?:[ \t]*[:=][ \t]*|[ \t]+)\S+/i;
const UNDERSCORE_PROVIDER_TOKEN =
  /(?:^|[^A-Za-z0-9])(?:sk|ghp|github_pat)_[A-Za-z0-9]+/i;
// Provider tokens are standalone, at least 20 payload characters, and include
// a long opaque alphanumeric run; ordinary hyphenated words do not qualify.
const HYPHENATED_SK_PROVIDER_TOKEN =
  /(?:^|[^A-Za-z0-9])sk-(?:(?:proj|ant-api03|ant|svcacct)-)?(?=[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-]))(?=[A-Za-z0-9_-]*[A-Za-z0-9]{16})[A-Za-z0-9_-]+/i;

/** Canonical credential-shaped string decision for governed local inputs. */
export function containsCredentialShapedContent(value: string): boolean {
  if (typeof value !== "string") return true;

  return (
    CREDENTIAL_ASSIGNMENT.test(value) ||
    UNDERSCORE_PROVIDER_TOKEN.test(value) ||
    HYPHENATED_SK_PROVIDER_TOKEN.test(value)
  );
}
