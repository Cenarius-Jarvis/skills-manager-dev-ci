// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
import { RemoteSkillWorkspace } from "./RemoteSkillWorkspace";
import type { DeviceWithStatus } from "../lib/tauri";

const backend = vi.hoisted(() => ({
  repositorySourcesList: vi.fn(),
  deviceSkillMirrorList: vi.fn(),
  deviceSkillMirrorRefresh: vi.fn(),
  deviceSkillMirrorRead: vi.fn(),
}));
vi.mock("../lib/tauri", () => backend);
vi.mock("react-i18next", () => ({
  useTranslation: () => ({ t: (key: string) => key, i18n: { language: "en" } }),
}));

it("opens a cached skill while its background refresh is offline", async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const host = document.createElement("div");
  document.body.append(host);
  const root = createRoot(host);
  const device: DeviceWithStatus = {
    id: "dev-remote", name: "E470C fixture", platform: "linux", created_at: 1,
    last_seen_at: null, online: false, skill_records: [],
  };
  backend.repositorySourcesList.mockResolvedValue([
    { id: "repo-other", device_id: "dev-other", name: "Other" },
    { id: "repo-fixture", device_id: device.id, name: "Fixture", branch: "main" },
  ]);
  backend.deviceSkillMirrorList.mockResolvedValue({
    head_commit: "a".repeat(40), synced_at: 10,
    skills: [{ path: "skills/fixture", name: "Cached fixture", has_draft: false }],
  });
  backend.deviceSkillMirrorRefresh.mockRejectedValue("offline");
  backend.deviceSkillMirrorRead.mockResolvedValue({
    content: "cached document", head_commit: "a".repeat(40), has_draft: false,
  });
  try {
    await act(async () => root.render(<RemoteSkillWorkspace device={device} onConfigure={() => {}} onQueued={() => {}} />));
    expect(backend.deviceSkillMirrorList).toHaveBeenCalledWith(device.id, "repo-fixture");
    expect(host.querySelector('[role="alert"]')?.textContent).toContain("offline");
    const skill = [...host.querySelectorAll("button")].find((button) => button.textContent?.includes("Cached fixture"));
    expect(skill).toBeDefined();
    await act(async () => skill?.click());
    expect(host.querySelector("textarea")?.value).toBe("cached document");
    expect(backend.deviceSkillMirrorRead).toHaveBeenCalledWith(device.id, "repo-fixture", "skills/fixture");
  } finally {
    await act(async () => root.unmount());
    host.remove();
    vi.unstubAllGlobals();
  }
});
