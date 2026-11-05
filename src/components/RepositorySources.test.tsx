// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { RepositorySources } from "./RepositorySources";

vi.mock("react-i18next", () => ({ useTranslation: () => ({ t: (key: string) => key }) }));
const api = vi.hoisted(() => ({
  repositorySourcesList: vi.fn(), repositorySourcesSnapshot: vi.fn(),
  repositorySourcesRefresh: vi.fn(), repositorySourcesAdd: vi.fn(), repositorySourcesRemove: vi.fn(),
}));
vi.mock("../lib/tauri", () => api);

let node: HTMLDivElement;
let root: Root;
beforeEach(() => {
  vi.clearAllMocks();
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  node = document.createElement("div");
  document.body.append(node);
  root = createRoot(node);
});
afterEach(async () => {
  await act(async () => root.unmount());
  node.remove();
  vi.unstubAllGlobals();
});

describe("independent repository sources", () => {
  it("keeps each cached source visible after one refresh fails", async () => {
    api.repositorySourcesList.mockResolvedValue([
      { id: "repo-a", name: "A", device_id: null, url: "https://example.invalid/a", branch: "main", skills_root: "", created_at: 1 },
      { id: "repo-b", name: "B", device_id: null, url: "https://example.invalid/b", branch: "main", skills_root: "", created_at: 1 },
    ]);
    api.repositorySourcesSnapshot.mockImplementation(async (id: string) => ({
      source_id: id, head_commit: id === "repo-a" ? "aaaa" : "bbbb", fetched_at: 1, observed_at: 1,
      skills: [{ name: "shared", relative_path: id === "repo-a" ? "skills/shared" : "other/shared" }],
    }));
    api.repositorySourcesRefresh.mockRejectedValue(new Error("fixture unavailable"));
    await act(async () => root.render(<RepositorySources devices={[]} />));
    const a = node.querySelector('[data-testid="repository-source-repo-a"]') as HTMLElement;
    const b = node.querySelector('[data-testid="repository-source-repo-b"]') as HTMLElement;
    expect(a.textContent).toContain("skills/shared");
    expect(b.textContent).toContain("other/shared");
    await act(async () => {
      (a.querySelector("button") as HTMLButtonElement).click();
    });
    expect(api.repositorySourcesRefresh).toHaveBeenCalledWith("repo-a");
    expect(a.querySelector('[role="alert"]')?.textContent).toContain("fixture unavailable");
    expect(a.textContent).toContain("skills/shared");
    expect(a.textContent).toContain("aaaa");
    expect(b.textContent).toContain("other/shared");
    expect(b.textContent).toContain("bbbb");
  });
});
