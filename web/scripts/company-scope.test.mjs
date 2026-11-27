import assert from "node:assert/strict";
import test from "node:test";
import { cleanScopeLine } from "../src/lib/company-scope-clean.ts";

test("cleanScopeLine cleans HackerOne/Bugcrowd tables, bullets, headers, and comments", () => {
  const raw = [
    "# Bug bounty program scope",
    "| Asset | Type | Eligible |",
    "| --- | --- | --- |",
    "| `*.example.com` | Domain | Yes |",
    "- api.example.com # production API",
    "* 198.51.100.0/24",
    "• 203.0.113.10",
    "sub.example.com\tDomain\tIn Scope",
  ];
  const cleaned = raw.map(cleanScopeLine).filter(Boolean);
  assert.deepEqual(cleaned, [
    "*.example.com",
    "api.example.com",
    "198.51.100.0/24",
    "203.0.113.10",
    "sub.example.com",
  ]);
});
