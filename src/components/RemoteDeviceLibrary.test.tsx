// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
import { RemoteDeviceLibrary } from "./RemoteDeviceLibrary";

vi.mock("react-i18next", () => ({ useTranslation: () => ({ t: (key: string) => key, i18n: { language: "en" } }) }));
vi.mock("react-router-dom", () => ({ useNavigate: () => vi.fn() }));
vi.mock("../views/Devices", () => ({ StateBadge: () => null }));

it("shows a fetch failure while keeping the last device report visible", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const host = document.createElement("div");
  document.body.append(host);
  const root = createRoot(host);
  const device = { id: "dev-remote", name: "fixture", platform: null, created_at: 1,
    last_seen_at: 2, online: false, skill_records: [] };
  try {
    await act(async () => root.render(<RemoteDeviceLibrary device={device}
      instructions={[]} loading={false} error="network unavailable" onRefresh={() => {}} />));
    expect(host.querySelector('[role="alert"]')?.textContent).toContain("network unavailable");
    expect(host.querySelector('[data-testid="remote-device-dev-remote"]')).not.toBeNull();
    expect(host.querySelector('[data-testid="remote-report-authenticity"]')?.textContent).toContain("devices.reportUnauthenticated");
  } finally {
    await act(async () => root.unmount());
    host.remove();
    vi.unstubAllGlobals();
  }
});

it("distinguishes unchecked, clean, and incomplete channel snapshots", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const host = document.createElement("div");
  document.body.append(host);
  const root = createRoot(host);
  const device = { id: "dev-remote", name: "fixture", platform: null, created_at: 1,
    last_seen_at: 2, online: false, skill_records: [] };
  const render = (snapshotWarnings: string[] | null) =>
    root.render(<RemoteDeviceLibrary device={device} instructions={[]} loading={false}
      snapshotWarnings={snapshotWarnings} onRefresh={() => {}} />);
  try {
    await act(async () => render(null));
    expect(host.querySelector('[data-testid="remote-snapshot-notice"]')?.textContent).toContain("devices.channelNotChecked");
    await act(async () => render([]));
    expect(host.querySelector('[data-testid="remote-snapshot-notice"]')?.textContent).toContain("devices.channelNoWarnings");
    await act(async () => render(["bad device report"]));
    const notice = host.querySelector('[data-testid="remote-snapshot-notice"]');
    expect(notice?.getAttribute("role")).toBe("alert");
    expect(notice?.textContent).toContain("bad device report");
  } finally {
    await act(async () => root.unmount());
    host.remove();
    vi.unstubAllGlobals();
  }
});
