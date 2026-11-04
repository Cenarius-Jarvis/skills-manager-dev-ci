// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { LocalInventoryPreview } from "./LocalInventoryPreview";

const mocks = vi.hoisted(() => ({ inspect: vi.fn() }));
vi.mock("react-i18next", () => ({ useTranslation: () => ({ t: (key: string) => key }) }));
vi.mock("../lib/tauri", () => ({ devicesInspectLocal: mocks.inspect }));

describe("local read-only inventory panel", () => {
  let host: HTMLDivElement;
  let root: ReturnType<typeof createRoot>;
  beforeEach(() => {
    vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
    mocks.inspect.mockReset();
    host = document.createElement("div");
    document.body.append(host);
    root = createRoot(host);
  });
  afterEach(async () => {
    await act(async () => root.unmount());
    host.remove();
    vi.unstubAllGlobals();
  });
  it("requires a path and labels incomplete scans", async () => {
    mocks.inspect.mockResolvedValue({ complete: false, skills: [{ name: "demo", symlink: true }], warnings: ["link outside approved root"] });
    await act(async () => root.render(<LocalInventoryPreview />));
    const button = host.querySelector("button")!;
    expect(button.disabled).toBe(true);
    const input = host.querySelector<HTMLInputElement>("#local-inventory-path")!;
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, "/fixture/agent");
      input.dispatchEvent(new Event("input", { bubbles: true }));
    });
    expect(button.disabled).toBe(false);
    await act(async () => { host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); });
    expect(mocks.inspect).toHaveBeenCalledWith("/fixture/agent", []);
    expect(host.textContent).toContain("localInventory.incomplete");
    expect(host.textContent).toContain("link outside approved root");
    expect(host.textContent).toContain("demo");
  });
  it("shows an error rather than a successful empty result", async () => {
    mocks.inspect.mockRejectedValue(new Error("offline"));
    await act(async () => root.render(<LocalInventoryPreview />));
    const input = host.querySelector<HTMLInputElement>("#local-inventory-path")!;
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, "/fixture/agent");
      input.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await act(async () => { host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); });
    expect(host.querySelector('[role="alert"]')?.textContent).toContain("localInventory.failed");
    expect(host.textContent).not.toContain("localInventory.complete");
  });
});
