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
  } finally {
    await act(async () => root.unmount());
    host.remove();
    vi.unstubAllGlobals();
  }
});
