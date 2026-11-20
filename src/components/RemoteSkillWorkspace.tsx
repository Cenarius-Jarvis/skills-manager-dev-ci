import { useEffect, useMemo, useState } from "react";
import { Loader2, RefreshCw } from "lucide-react";
import { useTranslation } from "react-i18next";
import * as api from "../lib/tauri";

function message(err: unknown): string {
  if (typeof err === "object" && err !== null && "message" in err) return String(err.message);
  return String(err);
}

export function RemoteSkillWorkspace({ device, onConfigure, onQueued }: {
  device: api.DeviceWithStatus;
  onConfigure: () => void;
  onQueued: () => void;
}) {
  const { t, i18n } = useTranslation();
  const [sources, setSources] = useState<api.RepositorySource[] | null>(null);
  const [sourceId, setSourceId] = useState("");
  const [snapshot, setSnapshot] = useState<api.DeviceSkillMirrorSnapshot | null>(null);
  const [query, setQuery] = useState("");
  const [path, setPath] = useState("");
  const [document, setDocument] = useState<api.DeviceSkillMirrorDocument | null>(null);
  const [draft, setDraft] = useState("");
  const [agent, setAgent] = useState("codex");
  const [busy, setBusy] = useState(false);
  const [loadingDocument, setLoadingDocument] = useState(false);
  const [error, setError] = useState("");
  const [status, setStatus] = useState("");
  const [confirming, setConfirming] = useState(false);

  const source = sources?.find((item) => item.id === sourceId);
  const agents = useMemo(() => [...new Set(["codex", ...device.skill_records.map((row) => row.agent_key)])], [device.skill_records]);

  useEffect(() => {
    let live = true;
    api.repositorySourcesList().then((all) => {
      if (!live) return;
      const bound = all.filter((item) => item.device_id === device.id);
      setSources(bound);
      setSourceId(bound[0]?.id ?? "");
    }).catch((err: unknown) => { if (live) setError(message(err)); });
    return () => { live = false; };
  }, [device.id]);

  useEffect(() => {
    if (!sourceId) return;
    let live = true;
    const load = async () => {
      try {
        const saved = await api.deviceSkillMirrorList(device.id, sourceId);
        if (!live) return;
        setSnapshot(saved);
        if (!saved.synced_at || Date.now() - saved.synced_at * 1000 > 5 * 60_000) {
          const latest = await api.deviceSkillMirrorRefresh(device.id, sourceId);
          if (live) setSnapshot(latest);
        }
      } catch (err) {
        if (live) setError(message(err));
      }
    };
    void load();
    return () => { live = false; };
  }, [device.id, sourceId]);

  const refresh = async () => {
    setBusy(true);
    setError("");
    try {
      setSnapshot(await api.deviceSkillMirrorRefresh(device.id, sourceId));
    } catch (err) {
      setError(message(err));
    } finally {
      setBusy(false);
    }
  };

  const open = async (skillPath: string) => {
    setPath(skillPath);
    setDocument(null);
    setConfirming(false);
    setStatus("");
    setError("");
    setLoadingDocument(true);
    try {
      const file = await api.deviceSkillMirrorRead(device.id, sourceId, skillPath);
      setDocument(file);
      setDraft(file.content);
    } catch (err) {
      setError(message(err));
    } finally {
      setLoadingDocument(false);
    }
  };

  const save = async (publish: boolean) => {
    if (!document) return;
    setBusy(true);
    setError("");
    setStatus("");
    try {
      let saved = document;
      if (draft !== document.content) {
        saved = await api.deviceSkillMirrorSave(device.id, sourceId, path, document.head_commit, draft);
        setDocument(saved);
      }
      if (!publish) {
        setStatus(t("remoteWorkspace.saved"));
      } else {
        const result = await api.deviceSkillPublish(device.id, sourceId, path, agent.trim());
        setStatus(t(result.queued ? "remoteWorkspace.queued" : "remoteWorkspace.queueFailed", { commit: result.commit.slice(0, 12) }));
        if (result.queued) {
          onQueued();
          const current = await api.deviceSkillMirrorRead(device.id, sourceId, path);
          setDocument(current);
          setDraft(current.content);
        }
      }
      setSnapshot(await api.deviceSkillMirrorList(device.id, sourceId));
    } catch (err) {
      setError(message(err));
    } finally {
      setConfirming(false);
      setBusy(false);
    }
  };

  const discard = async () => {
    if (!window.confirm(t("remoteWorkspace.discardConfirm"))) return;
    setBusy(true);
    setError("");
    try {
      const current = await api.deviceSkillMirrorDiscard(device.id, sourceId, path);
      setDocument(current);
      setDraft(current.content);
      setStatus("");
      setConfirming(false);
      setSnapshot(await api.deviceSkillMirrorList(device.id, sourceId));
    } catch (err) {
      setError(message(err));
    } finally {
      setBusy(false);
    }
  };

  const editable = draft !== document?.content;
  const cachedSkills = (snapshot?.skills ?? []).filter((entry) =>
    [entry.name, entry.path, entry.description ?? ""].some((value) => value.toLocaleLowerCase().includes(query.trim().toLocaleLowerCase())),
  );

  return (
    <section className="app-panel space-y-4 p-4" aria-label={t("remoteWorkspace.title")}>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="app-section-title">{t("remoteWorkspace.title")}</h2>
        <button type="button" className="app-button-secondary" onClick={onConfigure}>{t("remoteWorkspace.configure")}</button>
      </div>
      {error && <p role="alert" className="text-[13px] text-red-500">{error}</p>}
      {!sources && !error && <p role="status">{t("devices.loading")}</p>}
      {!source && sources?.length === 0 && <p className="text-[13px] text-muted">{t("remoteWorkspace.unbound")}</p>}
      {source && <>
        <div className="flex flex-wrap items-end gap-3">
          {sources && sources.length > 1 && <label className="flex flex-col gap-1">
            {t("remoteWorkspace.repository")}
            <select className="app-input" value={sourceId} disabled={busy || loadingDocument || editable && document !== null}
              onChange={(event) => {
                setSourceId(event.target.value);
                setSnapshot(null);
                setDocument(null);
                setDraft("");
                setPath("");
                setError("");
                setStatus("");
                setConfirming(false);
              }}>
              {sources.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}
            </select>
          </label>}
          <label className="flex flex-col gap-1">
            {t("remoteWorkspace.search")}
            <input className="app-input" type="search" value={query} onChange={(event) => setQuery(event.target.value)} />
          </label>
          <button type="button" className="app-button-secondary inline-flex items-center gap-2" disabled={busy}
            onClick={() => void refresh()}>
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
            {t("remoteWorkspace.refresh")}
          </button>
        </div>
        <p className="text-[13px] text-muted">
          {snapshot?.synced_at
            ? t("remoteWorkspace.snapshot", { time: new Date(snapshot.synced_at * 1000).toLocaleString(i18n.language), commit: snapshot.head_commit?.slice(0, 12) })
            : t("remoteWorkspace.empty")}
        </p>
        {snapshot?.head_commit && cachedSkills.length === 0 && <p className="text-[13px] text-muted">{t("remoteWorkspace.noMatches")}</p>}
        <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
          {cachedSkills.map((skill) => (
            <button type="button" key={skill.path} disabled={busy || loadingDocument || editable && document !== null}
              aria-pressed={path === skill.path} className="app-button-secondary min-h-11 flex-col items-start justify-start text-left"
              onClick={() => void open(skill.path)}>
              <span>{skill.name}{skill.has_draft ? " · " + t("remoteWorkspace.draft") : ""}</span>
              {skill.description && <span className="text-[12px] text-muted break-words">{skill.description}</span>}
            </button>
          ))}
        </div>
        {loadingDocument && <p role="status">{t("devices.loading")}</p>}
        {document && <div className="space-y-3 rounded-lg border border-border-subtle p-3">
          <label className="flex flex-col gap-2">
            <span className="font-medium">{path}/SKILL.md</span>
            <textarea className="app-input min-h-52 w-full font-mono text-[13px]" rows={12} value={draft}
              onChange={(event) => { setDraft(event.target.value); setConfirming(false); }}
              disabled={busy} spellCheck={false} />
          </label>
          <div className="flex flex-wrap items-end gap-3">
            <button type="button" className="app-button-secondary" disabled={busy || !editable}
              onClick={() => void save(false)}>{t("remoteWorkspace.save")}</button>
            {editable && <button type="button" className="app-button-secondary" disabled={busy}
              onClick={() => { setDraft(document.content); setConfirming(false); }}>{t("remoteWorkspace.reset")}</button>}
            {document.has_draft && <button type="button" className="app-button-secondary" disabled={busy}
              onClick={() => void discard()}>{t("remoteWorkspace.discard")}</button>}
            <label className="flex flex-col gap-1">
              {t("remoteWorkspace.target")}
              <input className="app-input" list="remote-workspace-agent-options" value={agent} disabled={busy}
                onChange={(event) => { setAgent(event.target.value); setConfirming(false); }} />
              <datalist id="remote-workspace-agent-options">{agents.map((key) => <option key={key} value={key} />)}</datalist>
            </label>
            <button type="button" className="app-button-primary" disabled={busy || !agent.trim() || !(document.has_draft || editable)}
              onClick={() => setConfirming(true)}>{t("remoteWorkspace.publish")}</button>
          </div>
          {confirming && <div className="space-y-2" role="group" aria-label={t("remoteWorkspace.publish")}>
            <p className="text-[13px]">{t("remoteWorkspace.confirm", { name: device.name, repo: source.name, branch: source.branch, agent })}</p>
            <div className="flex gap-2">
              <button type="button" className="app-button-primary" disabled={busy} onClick={() => void save(true)}>{t("remoteWorkspace.confirmPublish")}</button>
              <button type="button" className="app-button-secondary" disabled={busy} onClick={() => setConfirming(false)}>{t("common.cancel")}</button>
            </div>
          </div>}
          {status && <p role="status" className="text-[13px]">{status}</p>}
        </div>}
      </>}
    </section>
  );
}
