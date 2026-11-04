// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Devices } from "./Devices";
import type { DevicesPage } from "../lib/tauri";

vi.mock("react-i18next", () => ({ useTranslation: () => ({ t: (key: string) => key, i18n: { language: "en" } }) }));

const pageFixture: DevicesPage = {
  channel: {
    configured: true,
    url_redacted: "https://github.com/example/channel.git",
    branch: "skills-manager-devices",
    local_device_id: "dev-local",
    local_device_name: "workstation",
    online_threshold_secs: 900,
  },
  devices: [
    {
      id: "dev-1",
      name: "lab-box",
      platform: "linux",
      created_at: 1000,
      last_seen_at: 9_900_000,
      online: true,
      skill_records: [
        {
          device_id: "dev-1",
          agent_key: "openclaw",
          skill_name: "demo-skill",
          content_hash: "hash-1",
          deployed_at: 9_000_000,
          reported_commit: "c0ffee",
        },
      ],
    },
  ],
  instructions: [
    {
      id: "inst-1",
      device_id: "dev-1",
      action: "deploy",
      skill_url: "https://example.com/skills.git",
      skill_branch: "main",
      skill_subpath: "skills/demo",
      skill_name: "demo-skill",
      agent_key: "openclaw",
      created_at: 1000,
      expires_at: 2000,
      created_by: "workstation",
      instruction_commit: "abc",
      receipt_commit: "abc",
      state: "success",
      receipt_status: "success",
      receipt_reason: null,
      receipt_detail: null,
      receipt_at: 1500,
      executor_version: "test",
    },
  ],
};

const tauri = vi.hoisted(() => ({
  devicesGetPage: vi.fn(),
  devicesRefreshChannel: vi.fn(),
}));

vi.mock("../lib/tauri", () => tauri);

let container: HTMLDivElement;
let root: Root;

beforeEach(() => {
  vi.clearAllMocks();
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
});

afterEach(async () => {
  await act(async () => root.unmount());
  container.remove();
  vi.unstubAllGlobals();
});

describe("Devices page", () => {
  it("renders reported device skills and instruction states without claiming unreported success", async () => {
    tauri.devicesGetPage.mockResolvedValue(pageFixture);
    await act(async () => root.render(<Devices />));

    // Device identity and online state come from the report…
    expect(container.querySelector('[data-testid="device-dev-1"]')).not.toBeNull();
    expect(container.querySelector('[data-testid="device-online-true"]')).not.toBeNull();
    // …and so does the per-agent skill record.
    expect(container.textContent).toContain("lab-box");
    expect(container.textContent).toContain("demo-skill");
    expect(container.textContent).toContain("openclaw");

    // The instruction whose receipt matched its commit shows the reported
    // success state, and the request list is present.
    const badge = container.querySelector<HTMLElement>('[data-testid="instruction-inst-1"] [data-state]');
    expect(badge?.getAttribute("data-state")).toBe("success");
  });

  it("shows the channel setup form while the channel is unconfigured", async () => {
    tauri.devicesGetPage.mockResolvedValue({
      ...pageFixture,
      channel: { ...pageFixture.channel, configured: false },
    });
    await act(async () => root.render(<Devices />));

    const panel = container.querySelector('[data-testid="devices-not-configured"]');
    expect(panel).not.toBeNull();
    expect(panel!.querySelector('[data-testid="channel-url-input"]')).not.toBeNull();
    expect(panel!.querySelector('[data-testid="channel-save"]')).not.toBeNull();
  });

  it("surfaces fetch errors instead of rendering an empty page", async () => {
    tauri.devicesGetPage.mockRejectedValue(new Error("channel unreachable"));
    await act(async () => root.render(<Devices />));

    const error = container.querySelector('[data-testid="devices-error"]');
    expect(error).not.toBeNull();
    expect(error!.textContent).toContain("channel unreachable");
  });
});
