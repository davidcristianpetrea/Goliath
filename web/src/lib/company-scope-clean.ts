export function cleanScopeLine(raw: string): string {
  let s = raw.trim();
  if (!s) return "";
  // Ignore markdown table separator rows like | --- | --- |
  if (/^\|?[\s:|-]+\|?$/.test(s) && s.includes("-")) return "";
  // Strip common list bullets (- , * , • )
  s = s.replace(/^(?:[-*•]\s+|\d+[.)]\s+)/, "").trim();
  // Strip inline comments (# ...)
  s = s.replace(/\s+#.*$/, "").trim();
  if (!s || s.startsWith("#")) return "";
  // Extract first cell/token from pasted HackerOne/Bugcrowd/Intigriti table rows
  if (s.includes("|")) {
    const cells = s
      .split("|")
      .map((c) => c.trim())
      .filter(Boolean);
    if (cells.length > 0) {
      const first = cells[0].replace(/^`+|`+$/g, "").trim();
      if (/^(asset|target|identifier|scope|domain|url)$/i.test(first)) return "";
      s = first;
    }
  } else if (s.includes("\t")) {
    const first = s.split("\t")[0].trim();
    if (/^(asset|target|identifier|scope|domain|url)$/i.test(first)) return "";
    s = first;
  }
  return s.replace(/^`+|`+$/g, "").trim();
}
