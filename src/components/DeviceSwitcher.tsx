import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { Check, ChevronDown, Monitor, Settings2 } from "lucide-react";
import { cn } from "../utils";
import { useDeviceView } from "../context/DeviceViewContext";

/** Sidebar-top context switcher: pick which machine the library-facing UI
 * looks at — this machine (full features) or any registered remote device
 * (read-only report + remote deployments). Mirrors the preset dropdown
 * interaction the app already uses. */
export function DeviceSwitcher() {
  const { t } = useTranslation();
  const { view, setView, devicesPage, devicesLoading } = useDeviceView();
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();

  useEffect(() => {
    if (!open) return;
    const handlePointer = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", handlePointer);
    document.addEventListener("keydown", handleEscape);
    return () => {
      document.removeEventListener("mousedown", handlePointer);
      document.removeEventListener("keydown", handleEscape);
    };
  }, [open]);

  const currentLabel =
    view === "local"
      ? t("deviceSwitcher.local")
      : devicesPage?.devices.find((d) => d.id === view)?.name ?? view;
  const isRemote = view !== "local";

  return (
    <div ref={containerRef} className="relative px-2.5 shrink-0" data-testid="device-switcher">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        aria-haspopup="listbox"
        data-testid="device-switcher-trigger"
        className={cn(
          "flex w-full items-center gap-2 rounded-lg border px-2.5 py-[7px] text-left text-[14px] leading-5 transition-colors outline-none",
          open
            ? "border-accent-border bg-surface-hover text-primary"
            : "border-border-subtle bg-surface text-secondary hover:border-border hover:text-primary"
        )}
      >
        <Monitor className={cn("h-4 w-4 shrink-0", isRemote ? "text-accent" : "text-muted")} />
        <span className="min-w-0 flex-1 truncate font-medium">{currentLabel}</span>
        {isRemote && (
          <span className="shrink-0 rounded-full border border-accent/30 bg-accent/10 px-1.5 text-[11px] text-accent">
            {t("deviceSwitcher.remoteTag")}
          </span>
        )}
        <ChevronDown
          className={cn("h-3.5 w-3.5 shrink-0 text-muted transition-transform", open && "rotate-180")}
        />
      </button>

      {open && (
        <div
          role="listbox"
          className="absolute left-2.5 right-2.5 top-full z-50 mt-1 rounded-xl border border-border bg-surface p-1.5 shadow-2xl"
          data-testid="device-switcher-menu"
        >
          {/* Local machine */}
          <button
            role="option"
            aria-selected={view === "local"}
            onClick={() => {
              setView("local");
              setOpen(false);
            }}
            className={cn(
              "flex w-full items-center gap-2 rounded-lg px-2.5 py-2 text-left text-[13px] transition-colors",
              view === "local" ? "bg-accent-bg text-primary" : "text-secondary hover:bg-surface-hover"
            )}
          >
            <Monitor className="h-3.5 w-3.5 shrink-0 text-muted" />
            <span className="min-w-0 flex-1">
              <span className="block truncate font-medium">{t("deviceSwitcher.local")}</span>
              <span className="block truncate text-[12px] text-muted">
                {t("deviceSwitcher.localHint")}
              </span>
            </span>
            {view === "local" && <Check className="h-3.5 w-3.5 shrink-0 text-accent" />}
          </button>

          {/* Registered remote devices */}
          {(devicesPage?.devices ?? []).map((device) => (
            <button
              key={device.id}
              role="option"
              aria-selected={view === device.id}
              onClick={() => {
                setView(device.id);
                setOpen(false);
              }}
              className={cn(
                "flex w-full items-center gap-2 rounded-lg px-2.5 py-2 text-left text-[13px] transition-colors",
                view === device.id ? "bg-accent-bg text-primary" : "text-secondary hover:bg-surface-hover"
              )}
            >
              <span
                className={cn(
                  "h-1.5 w-1.5 shrink-0 rounded-full",
                  device.online ? "bg-emerald-400" : "bg-surface-active"
                )}
                title={device.online ? t("devices.online") : t("devices.offline")}
              />
              <span className="min-w-0 flex-1">
                <span className="block truncate font-medium">{device.name}</span>
                <span className="block truncate text-[12px] text-muted">
                  {t("deviceSwitcher.remoteHint")}
                  {device.platform ? ` · ${device.platform}` : ""}
                </span>
              </span>
              {view === device.id && <Check className="h-3.5 w-3.5 shrink-0 text-accent" />}
            </button>
          ))}

          {(devicesPage?.devices ?? []).length > 0 && <div className="my-1 border-t border-border-subtle" />}

          {/* Management entry */}
          <button
            role="option"
            aria-selected={false}
            onClick={() => {
              setOpen(false);
              navigate("/devices");
            }}
            className="flex w-full items-center gap-2 rounded-lg px-2.5 py-2 text-left text-[13px] text-secondary transition-colors hover:bg-surface-hover"
          >
            <Settings2 className="h-3.5 w-3.5 shrink-0 text-muted" />
            <span className="flex-1 truncate">{t("deviceSwitcher.manage")}</span>
          </button>

          {devicesLoading && (
            <div className="px-2.5 py-1.5 text-[12px] text-muted">{t("common.loading")}</div>
          )}
        </div>
      )}
    </div>
  );
}
