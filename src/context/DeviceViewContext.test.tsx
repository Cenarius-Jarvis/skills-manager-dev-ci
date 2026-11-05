// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DeviceViewProvider, useDeviceView } from "./DeviceViewContext";

const api = vi.hoisted(() => ({ devicesGetPage: vi.fn(), devicesRefreshChannel: vi.fn() }));
vi.mock("../lib/tauri", () => api);

const page = (name: string) => ({
  channel: { configured: true, url_redacted: "fixture", branch: "test",
    local_device_id: "local", local_device_name: "local", online_threshold_secs: 60 },
  devices: [{ id: "remote", name, platform: null, created_at: 1, last_seen_at: 2,
    online: true, skill_records: [] }],
  instructions: [],
});

function Probe() {
  const { devicesPage, refreshDevices, devicesError } = useDeviceView();
  return <div>
    <span data-testid="device">{devicesPage?.devices[0]?.name ?? "none"}</span>
    <span data-testid="error">{devicesError ?? ""}</span>
    <button onClick={() => void refreshDevices()}>refresh</button>
  </div>;
}

describe("remote device refresh", () => {
  let host: HTMLDivElement;
  let root: Root;
  beforeEach(() => {
    vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
    api.devicesGetPage.mockReset();
    api.devicesRefreshChannel.mockReset();
    localStorage.clear();
    host = document.createElement("div");
    document.body.append(host);
    root = createRoot(host);
  });
  afterEach(async () => {
    await act(async () => root.unmount());
    host.remove();
    vi.unstubAllGlobals();
  });
  it("loads cached state first, then actually fetches remote channel on refresh", async () => {
    api.devicesGetPage.mockResolvedValue(page("old"));
    api.devicesRefreshChannel.mockResolvedValue(page("new"));
    await act(async () => root.render(<DeviceViewProvider><Probe /></DeviceViewProvider>));
    expect(host.querySelector('[data-testid="device"]')?.textContent).toBe("old");
    expect(api.devicesRefreshChannel).not.toHaveBeenCalled();
    await act(async () => host.querySelector("button")!.click());
    expect(api.devicesRefreshChannel).toHaveBeenCalledOnce();
    expect(host.querySelector('[data-testid="device"]')?.textContent).toBe("new");
  });
  it("retains the last report and displays the actual fetch failure", async () => {
    api.devicesGetPage.mockResolvedValue(page("last-good"));
    api.devicesRefreshChannel.mockRejectedValue({ message: "network unavailable" });
    await act(async () => root.render(<DeviceViewProvider><Probe /></DeviceViewProvider>));
    await act(async () => host.querySelector("button")!.click());
    expect(host.querySelector('[data-testid="device"]')?.textContent).toBe("last-good");
    expect(host.querySelector('[data-testid="error"]')?.textContent).toBe("network unavailable");
  });
});
