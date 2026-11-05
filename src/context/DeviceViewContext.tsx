/* eslint-disable react-refresh/only-export-components */
import { createContext, useCallback, useContext, useEffect, useState } from "react";
import type { ReactNode } from "react";
import * as api from "../lib/tauri";
import type { DevicesPage } from "../lib/tauri";

/** Which machine the library-facing UI is looking at: "local" or a device id
 * from the channel registry. Persisted; falls back to "local" if the stored
 * device stops existing. */
export type DeviceView = "local" | string;

interface DeviceViewContextValue {
  view: DeviceView;
  setView: (v: DeviceView) => void;
  devicesPage: DevicesPage | null;
  refreshDevices: () => Promise<void>;
  devicesLoading: boolean;
  devicesError: string | null;
}

const Ctx = createContext<DeviceViewContextValue | null>(null);

const STORAGE_KEY = "skills-manager:device-view";

function formatDeviceError(err: unknown): string {
  if (err instanceof Error) return err.message;
  if (typeof err === "object" && err !== null && "message" in err) {
    const message = (err as { message: unknown }).message;
    if (typeof message === "string" && message) return message;
  }
  return String(err);
}

export function DeviceViewProvider({ children }: { children: ReactNode }) {
  const [view, setViewState] = useState<DeviceView>(() => {
    try {
      return localStorage.getItem(STORAGE_KEY) || "local";
    } catch {
      return "local";
    }
  });
  const [devicesPage, setDevicesPage] = useState<DevicesPage | null>(null);
  const [devicesLoading, setDevicesLoading] = useState(false);
  const [devicesError, setDevicesError] = useState<string | null>(null);

  const applyPage = useCallback((page: DevicesPage) => {
    setDevicesPage(page);
    // Only a successful page read can invalidate a remembered selection.
    setViewState((current) => {
      if (current !== "local" && !page.devices.some((d) => d.id === current)) {
        try { localStorage.setItem(STORAGE_KEY, "local"); } catch { /* unavailable */ }
        return "local";
      }
      return current;
    });
  }, []);

  // Load the local projection at startup without requiring network access.
  useEffect(() => {
    let active = true;
    setDevicesLoading(true);
    void api.devicesGetPage()
      .then((page) => {
        if (active) { applyPage(page); setDevicesError(null); }
      })
      .catch((err: unknown) => {
        if (active) setDevicesError(formatDeviceError(err));
      })
      .finally(() => { if (active) setDevicesLoading(false); });
    return () => { active = false; };
  }, [applyPage]);

  // A user refresh must fetch the channel, not just reread cached DB rows.
  const refreshDevices = useCallback(async () => {
    setDevicesLoading(true);
    setDevicesError(null);
    try {
      applyPage(await api.devicesRefreshChannel());
    } catch (err) {
      // Retain the previous projection and its original reported timestamps.
      setDevicesError(formatDeviceError(err));
    } finally {
      setDevicesLoading(false);
    }
  }, [applyPage]);

  const setView = useCallback((v: DeviceView) => {
    setViewState(v);
    try {
      localStorage.setItem(STORAGE_KEY, v);
    } catch {
      /* ignore */
    }
  }, []);

  return (
    <Ctx.Provider value={{ view, setView, devicesPage, refreshDevices, devicesLoading, devicesError }}>
      {children}
    </Ctx.Provider>
  );
}

export function useDeviceView(): DeviceViewContextValue {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useDeviceView must be used within DeviceViewProvider");
  return ctx;
}
