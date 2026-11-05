import { useEffect, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import * as api from "../lib/tauri";
import type { DeviceWithStatus, RepositorySnapshot, RepositorySource } from "../lib/tauri";

function message(err: unknown): string {
  if (err instanceof Error) return err.message;
  if (typeof err === "object" && err !== null && "message" in err) {
    return String((err as { message: unknown }).message);
  }
  return String(err);
}

/** Independent repository snapshots. Explicit actions only: no deployment or push. */
export function RepositorySources({ devices }: { devices: DeviceWithStatus[] }) {
  const { t } = useTranslation();
  const [sources, setSources] = useState<RepositorySource[]>([]);
  const [snapshots, setSnapshots] = useState<Record<string, RepositorySnapshot | null>>({});
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("loading");
  const [name, setName] = useState("");
  const [deviceId, setDeviceId] = useState("");
  const [url, setUrl] = useState("");
  const [branch, setBranch] = useState("main");
  const [root, setRoot] = useState("");

  useEffect(() => {
    let active = true;
    void (async () => {
      try {
        const list = await api.repositorySourcesList();
        const entries = await Promise.all(list.map(async (source) => {
          try { return { id: source.id, snapshot: await api.repositorySourcesSnapshot(source.id), error: "" }; }
          catch (err) { return { id: source.id, snapshot: null, error: message(err) }; }
        }));
        if (!active) return;
        setSources(list);
        setSnapshots(Object.fromEntries(entries.map(({ id, snapshot }) => [id, snapshot])));
        setErrors(Object.fromEntries(entries.filter((entry) => entry.error).map(({ id, error }) => [id, error])));
      } catch (err) {
        if (active) setError(message(err));
      } finally {
        if (active) setBusy("");
      }
    })();
    return () => { active = false; };
  }, []);

  async function add(event: FormEvent) {
    event.preventDefault();
    if (busy || !name.trim() || !url.trim() || !branch.trim()) return;
    setBusy("add"); setError("");
    try {
      const source = await api.repositorySourcesAdd(name.trim(), deviceId || null, url.trim(), branch.trim(), root.trim());
      setSources((current) => [...current, source]);
      setName(""); setUrl(""); setRoot("");
    } catch (err) { setError(message(err)); }
    finally { setBusy(""); }
  }
  async function refresh(id: string) {
    setBusy(id); setErrors((current) => ({ ...current, [id]: "" }));
    try {
      const snapshot = await api.repositorySourcesRefresh(id);
      setSnapshots((current) => ({ ...current, [id]: snapshot }));
    } catch (err) { setErrors((current) => ({ ...current, [id]: message(err) })); }
    finally { setBusy(""); }
  }
  async function remove(id: string) {
    setBusy(id); setErrors((current) => ({ ...current, [id]: "" }));
    try {
      if (await api.repositorySourcesRemove(id)) {
        setSources((current) => current.filter((source) => source.id !== id));
        setSnapshots((current) => { const next = { ...current }; delete next[id]; return next; });
      }
    } catch (err) { setErrors((current) => ({ ...current, [id]: message(err) })); }
    finally { setBusy(""); }
  }

  return (
    <details className="app-panel p-4" data-testid="repository-sources">
      <summary className="cursor-pointer font-medium">{t("repositorySources.title")}</summary>
      <p className="mt-2 text-[13px] text-muted">{t("repositorySources.hint")}</p>
      <form className="mt-3 flex flex-wrap items-end gap-2" onSubmit={(event) => void add(event)}>
        <label className="flex flex-col gap-1"><span>{t("repositorySources.name")}</span>
          <input className="app-input" value={name} onChange={(event) => setName(event.target.value)} required /></label>
        <label className="flex flex-col gap-1"><span>{t("repositorySources.device")}</span>
          <select className="app-input" value={deviceId} onChange={(event) => setDeviceId(event.target.value)}>
            <option value="">{t("repositorySources.unassigned")}</option>
            {devices.map((device) => <option key={device.id} value={device.id}>{device.name}</option>)}
          </select></label>
        <label className="flex flex-col gap-1"><span>{t("repositorySources.url")}</span>
          <input className="app-input w-72" value={url} onChange={(event) => setUrl(event.target.value)} required /></label>
        <label className="flex flex-col gap-1"><span>{t("repositorySources.branch")}</span>
          <input className="app-input w-28" value={branch} onChange={(event) => setBranch(event.target.value)} required /></label>
        <label className="flex flex-col gap-1"><span>{t("repositorySources.root")}</span>
          <input className="app-input w-40" value={root} onChange={(event) => setRoot(event.target.value)} /></label>
        <button className="app-button-primary" disabled={!!busy || !name.trim() || !url.trim() || !branch.trim()}>
          {t("repositorySources.add")}
        </button>
      </form>
      {error && <p role="alert" className="mt-2 text-red-600 dark:text-red-400">{error}</p>}
      <div className="mt-4 flex flex-col gap-3">
        {sources.length === 0 && <p className="text-[13px] text-muted">{t("repositorySources.empty")}</p>}
        {sources.map((source) => {
          const snapshot = snapshots[source.id];
          const owner = devices.find((device) => device.id === source.device_id);
          return <section key={source.id} className="rounded-lg border border-border-subtle p-3" data-testid={`repository-source-${source.id}`}>
            <div className="flex flex-wrap items-center gap-2">
              <strong>{source.name}</strong>
              <span className="text-muted">{owner?.name ?? source.device_id ?? t("repositorySources.unassigned")}</span>
              <span className="text-muted">{source.branch}</span>
              <button type="button" className="app-button-secondary" disabled={!!busy} onClick={() => void refresh(source.id)}>
                {busy === source.id ? t("repositorySources.working") : t("repositorySources.refresh")}
              </button>
              <button type="button" className="app-button-secondary" disabled={!!busy} onClick={() => void remove(source.id)}>
                {t("repositorySources.remove")}
              </button>
            </div>
            {errors[source.id] && <p role="alert" className="mt-2 text-red-600 dark:text-red-400">{t("repositorySources.refreshFailed")} {errors[source.id]}</p>}
            {snapshot ? <>
              <p className="mt-2 text-[12px] text-muted">{t("repositorySources.commit")}: {snapshot.head_commit} · {new Date(snapshot.fetched_at * 1000).toLocaleString()}</p>
              {snapshot.skills.length ? <ul className="mt-2 list-inside list-disc">{snapshot.skills.map((skill) =>
                <li key={skill.relative_path}>{skill.relative_path}</li>)}</ul> : <p className="mt-2 text-muted">{t("repositorySources.noSkills")}</p>}
            </> : <p className="mt-2 text-muted">{t("repositorySources.notFetched")}</p>}
          </section>;
        })}
      </div>
    </details>
  );
}
