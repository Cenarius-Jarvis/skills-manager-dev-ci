import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import * as api from "../lib/tauri";

export function DeviceWorkerSettings() {
  const { t, i18n } = useTranslation();
  const [settings, setSettings] = useState<api.DeviceWorkerStatus | null>(null);
  const [tools, setTools] = useState<api.ToolInfo[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let active = true;
    const load = () => api.deviceWorkerStatus().then((next) => { if (active) setSettings(next); })
      .catch((failure: unknown) => { if (active) setError(String(failure)); });
    void load();
    void api.getToolStatus().then((list) => { if (active) setTools(list); }).catch(() => {});
    const timer = window.setInterval(() => void load(), 15_000);
    return () => { active = false; window.clearInterval(timer); };
  }, []);

  const change = async (run: () => Promise<api.DeviceWorkerStatus>) => {
    setBusy(true);
    setError("");
    try { setSettings(await run()); }
    catch (failure) { setError(String(failure)); }
    finally { setBusy(false); }
  };

  return (
    <details className="app-panel p-4">
      <summary className="cursor-pointer font-medium">{t("remoteWorkspace.worker")}</summary>
      <p className="mt-2 text-[13px] text-muted">{t("remoteWorkspace.workerHint")}</p>
      {error && <p role="alert" className="mt-2 text-[13px] text-red-500">{error}</p>}
      {settings && <div className="mt-3 space-y-3">
        <fieldset className="flex flex-wrap gap-x-4 gap-y-2" disabled={busy}>
          <legend className="mb-1 text-[13px] font-medium">{t("remoteWorkspace.authorize")}</legend>
          {tools.filter((tool) => tool.installed || settings.authorized_agents.includes(tool.key)).map((tool) => (
            <label key={tool.key} className="flex min-h-9 items-center gap-2">
              <input type="checkbox" checked={settings.authorized_agents.includes(tool.key)}
                onChange={(event) => void change(() => api.deviceWorkerAuthorize(tool.key, event.target.checked))} />
              {tool.display_name}
            </label>
          ))}
        </fieldset>
        <label className="flex min-h-9 items-center gap-2">
          <input type="checkbox" checked={settings.github_ssh} disabled={busy}
            onChange={(event) => void change(() => api.deviceWorkerSet(settings.enabled, event.target.checked))} />
          {t("remoteWorkspace.githubSsh")}
        </label>
        <button className="app-button-secondary" type="button" disabled={busy || !settings.enabled && !settings.authorized_agents.length}
          onClick={() => void change(() => api.deviceWorkerSet(!settings.enabled, settings.github_ssh))}>
          {t(settings.enabled ? "remoteWorkspace.stopWorker" : "remoteWorkspace.startWorker")}
        </button>
        {settings.last_success_at && <p className="text-[13px]" role="status">{t("remoteWorkspace.lastPoll", {
          time: new Date(settings.last_success_at * 1000).toLocaleString(i18n.language),
        })}</p>}
        {settings.last_error && <p className="text-[13px] text-red-500" role="status">{settings.last_error}</p>}
      </div>}
    </details>
  );
}
