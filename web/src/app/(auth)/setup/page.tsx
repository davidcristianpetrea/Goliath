"use client";

import { useEffect, useState } from "react";

import { useRouter } from "next/navigation";

import { GoliathLogo } from "@/components/goliath-logo";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { t } from "@/i18n";
import { api } from "@/lib/api";
import { auth } from "@/lib/auth";

export default function SetupPage() {
  const router = useRouter();
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [setupToken, setSetupToken] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [checking, setChecking] = useState(true);
  // when the initialization state cannot be fetched, do not default to "not initialized" — that would show the setup form to an
  // instance that already has a password, and following it would overwrite the original. Close the entrance instead.
  const [unavailable, setUnavailable] = useState(false);

  useEffect(() => {
    api
      .authStatus()
      .then(({ initialized }) => {
        if (initialized) router.replace("/login");
      })
      .catch((err) => {
        setError(err instanceof Error ? err.message : t("Unable to connect to the backend service"));
        setUnavailable(true);
      })
      .finally(() => setChecking(false));
  }, [router]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (password !== confirm) {
      setError(t("The two passwords do not match"));
      return;
    }
    if (password.length < 12) {
      setError(t("Password must be at least 12 characters"));
      return;
    }
    setLoading(true);
    setError("");
    try {
      const { token } = await api.initPassword(password, setupToken.trim());
      auth.setToken(token);
      router.replace("/function/tasks");
    } catch (err) {
      setError(err instanceof Error ? err.message : t("Initialization failed"));
    } finally {
      setLoading(false);
    }
  }

  if (checking) return null;

  return (
    <div className="flex min-h-dvh">
      {/* Left panel — always dark regardless of theme mode */}
      <div className="hidden flex-col items-center justify-center border-r border-white/10 bg-zinc-950 p-12 text-center text-zinc-50 lg:flex lg:w-1/3">
        <div className="relative flex flex-col items-center justify-center gap-6">
          <div className="absolute size-80 rounded-full border border-primary/5 dark:border-primary/10" />
          <div className="absolute size-60 rounded-full border border-primary/10 dark:border-primary/20" />
          <div className="absolute size-40 rounded-full border border-primary/15 dark:border-primary/30" />
          <GoliathLogo variant="full" className="relative scale-125 text-zinc-50" />
        </div>
      </div>

      {/* Right panel */}
      <div className="flex w-full items-center justify-center bg-background p-6 sm:p-8 lg:w-2/3">
        <div className="w-full max-w-md space-y-8 py-8 sm:py-16 lg:space-y-10 lg:py-24">
          <div className="flex justify-center lg:hidden">
            <GoliathLogo variant="full" />
          </div>
          <div className="space-y-3 text-center">
            <h2 className="text-2xl font-medium tracking-tight">{unavailable ? t("Cannot confirm initialization state") : t("Set initial password")}</h2>
            <p className="mx-auto max-w-xl text-muted-foreground">
              {unavailable
                ? t(
                    "The backend or database is temporarily unavailable. To avoid overwriting a password already set on this instance, setup is temporarily closed — restore the service and try again.",
                  )
                : t(
                    "First time using Goliath? Enter the setup token from the server log, then set a login password for the account (at least 12 characters)",
                  )}
            </p>
          </div>
          {unavailable ? (
            <div className="flex flex-col gap-4">
              {error && <p className="text-center text-sm text-destructive">{error}</p>}
              <Button type="button" className="w-full" onClick={() => window.location.reload()}>
                {t("Retry")}
              </Button>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="flex flex-col gap-4">
              <div className="space-y-1.5">
                <Label htmlFor="setup-token">{t("Setup token")}</Label>
                <Input
                  id="setup-token"
                  value={setupToken}
                  onChange={(e) => setSetupToken(e.target.value)}
                  placeholder={t("Printed in the server log at startup")}
                  autoFocus
                  autoComplete="off"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="password">{t("New password")}</Label>
                <Input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder={t("At least 12 characters")}
                  autoComplete="new-password"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="confirm">{t("Confirm password")}</Label>
                <Input
                  id="confirm"
                  type="password"
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  placeholder={t("Enter the password again")}
                  autoComplete="new-password"
                />
              </div>
              {error && <p className="text-sm text-destructive" role="alert">{error}</p>}
              <Button
                type="submit"
                className="w-full"
                disabled={loading || !setupToken.trim() || !password || !confirm}
              >
                {loading ? t("Saving...") : t("Set password and sign in")}
              </Button>
              <p className="rounded-md border bg-muted/40 px-3 py-2 text-xs text-muted-foreground">
                {t("Traffic capture is off by default. Enable it in System settings after setup if you need provable HTTP findings — captured traffic is required for findings to prove goals.")}
              </p>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}
