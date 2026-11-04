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
}

const Ctx = createContext<DeviceViewContextValue | null>(null);

const STORAGE_KEY = "skills-manager:device-view";

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

  const refreshDevices = useCallback(async () => {
    setDevicesLoading(true);
    try {
      const page = await api.devicesGetPage();
      setDevicesPage(page);
      // The stored view may reference a device that was removed elsewhere.
      setViewState((current) => {
        if (current !== "local" && !page.devices.some((d) => d.id === current)) {
          try {
            localStorage.setItem(STORAGE_KEY, "local");
          } catch {
            /* ignore */
          }
          return "local";
        }
        return current;
      });
    } catch {
      // Channel unconfigured or unreachable: keep the last known page so the
      // switcher still renders. The UI surfaces freshness separately.
    } finally {
      setDevicesLoading(false);
    }
  }, []);

  useEffect(() => {
    void refreshDevices();
  }, [refreshDevices]);

  const setView = useCallback((v: DeviceView) => {
    setViewState(v);
    try {
      localStorage.setItem(STORAGE_KEY, v);
    } catch {
      /* ignore */
    }
  }, []);

  return (
    <Ctx.Provider value={{ view, setView, devicesPage, refreshDevices, devicesLoading }}>
      {children}
    </Ctx.Provider>
  );
}

export function useDeviceView(): DeviceViewContextValue {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useDeviceView must be used within DeviceViewProvider");
  return ctx;
}
