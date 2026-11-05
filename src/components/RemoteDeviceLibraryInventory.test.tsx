// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { RemoteDeviceLibrary } from "./RemoteDeviceLibrary";
import type { DeviceWithStatus } from "../lib/tauri";

vi.mock("react-i18next", () => ({
  useTranslation: () => ({ t: (key: string) => key, i18n: { language: "en" } }),
}));

let container: HTMLDivElement;
let root: Root;
beforeEach(() => {
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

const device: DeviceWithStatus = {
  id: "dev-test", name: "remote", platform: "linux", created_at: 1,
  last_seen_at: 100, online: true,
  skill_records: [{
    device_id: "dev-test", agent_key: "codex", skill_name: "deployed-skill",
    content_hash: null, deployed_at: null, reported_commit: null,
  }],
  library: {
    state: "complete", reported_at: 100,
    skills: [{ id: "s1", name: "unassigned-skill", enabled: true }],
  },
};

it("shows registered library separately from agent deployments", async () => {
  await act(async () => root.render(
    <MemoryRouter><RemoteDeviceLibrary device={device} instructions={[]} loading={false} onRefresh={() => {}} /></MemoryRouter>,
  ));
  const central = container.querySelector('[data-testid="remote-central-library"]');
  expect(central?.textContent).toContain("unassigned-skill");
  expect(central?.textContent).not.toContain("deployed-skill");
  expect(container.textContent).toContain("codex");
  expect(container.textContent).toContain("deployed-skill");
});

it("marks a missing current report while retaining last known library and does not treat unknown as empty", async () => {
  const missing: DeviceWithStatus = { ...device, library: { ...device.library!, state: "missing" } };
  await act(async () => root.render(
    <MemoryRouter><RemoteDeviceLibrary device={missing} instructions={[]} loading={false} onRefresh={() => {}} /></MemoryRouter>,
  ));
  expect(container.querySelector('[data-testid="remote-library-state"]')?.textContent).toContain("devices.libraryState.missing");
  expect(container.querySelector('[data-testid="remote-library-skills"]')?.textContent).toContain("unassigned-skill");
  const never: DeviceWithStatus = { ...device, library: undefined };
  await act(async () => root.render(
    <MemoryRouter><RemoteDeviceLibrary device={never} instructions={[]} loading={false} onRefresh={() => {}} /></MemoryRouter>,
  ));
  expect(container.querySelector('[data-testid="remote-library-state"]')?.textContent).toContain("devices.libraryState.missing");
  expect(container.querySelector('[data-testid="remote-central-library"]')?.textContent).not.toContain("devices.libraryEmpty");
});
