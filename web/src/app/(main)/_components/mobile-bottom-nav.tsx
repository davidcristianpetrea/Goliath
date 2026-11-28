"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { Bug, LayoutDashboard, Menu, MessageSquare, Target } from "lucide-react";

import { useSidebar } from "@/components/ui/sidebar";
import { t } from "@/i18n";
import { cn } from "@/lib/utils";

const NAV_ITEMS = [
  { id: "dashboard", label: t("Dashboard"), href: "/dashboard", icon: LayoutDashboard },
  { id: "tasks", label: t("Tasks"), href: "/function/tasks", icon: Target },
  { id: "findings", label: t("Findings"), href: "/function/findings", icon: Bug },
  { id: "chat", label: t("Chat"), href: "/chat", icon: MessageSquare },
] as const;

export function MobileBottomNav() {
  const pathname = usePathname();
  const { toggleSidebar } = useSidebar();

  return (
    <nav
      aria-label={t("Mobile navigation")}
      className="fixed inset-x-0 bottom-0 z-40 grid grid-cols-5 border-t bg-background/90 backdrop-blur-md pb-[env(safe-area-inset-bottom)] md:hidden"
    >
      {NAV_ITEMS.map((item) => {
        const Icon = item.icon;
        const active = pathname === item.href || pathname.startsWith(`${item.href}/`);
        return (
          <Link
            key={item.id}
            prefetch={false}
            href={item.href}
            aria-current={active ? "page" : undefined}
            className={cn(
              "flex min-h-14 flex-col items-center justify-center gap-0.5 px-1 text-[10px] font-medium transition-colors",
              active ? "text-primary" : "text-muted-foreground hover:text-foreground",
            )}
          >
            <Icon className="size-4.5" aria-hidden="true" />
            <span className="max-w-full truncate">{item.label}</span>
          </Link>
        );
      })}
      <button
        type="button"
        onClick={toggleSidebar}
        aria-label={t("Menu")}
        className="flex min-h-14 flex-col items-center justify-center gap-0.5 px-1 text-[10px] font-medium text-muted-foreground transition-colors hover:text-foreground"
      >
        <Menu className="size-4.5" aria-hidden="true" />
        <span className="max-w-full truncate">{t("Menu")}</span>
      </button>
    </nav>
  );
}
