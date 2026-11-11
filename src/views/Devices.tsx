import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import {
  Loader2,
  Monitor,
  RefreshCw,
  CheckCircle2,
  XCircle,
  Clock,
  WifiOff,
  AlertTriangle,
  CircleDashed,
  Plus,
  Send,
} from "lucide-react";
import { LocalInventoryPreview } from "../components/LocalInventoryPreview";
import { RepositorySources } from "../components/RepositorySources";
import * as api from "../lib/tauri";
import type { DeviceTaskState, DeviceWithStatus } from "../lib/tauri";

/** Visual + label mapping for the seven task states (docs/devices.md).
 * "success" is always backed by the device's own receipt — never by the
 * mere existence of an instruction or a commit. */
function stateMeta(
  state: DeviceTaskState,
  t: (key: string) => string,
): {
  label: string;
  className: string;
  icon: typeof CheckCircle2;
} {
  switch (state) {
    case "success":
      return {
        label: t("devices.state.success"),
        className: "border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400",
        icon: CheckCircle2,
      };
    case "failed":
      return {
        label: t("devices.state.failed"),
        className: "border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-400",
        icon: XCircle,
      };
    case "executing":
      return {
        label: t("devices.state.executing"),
        className: "border-blue-500/30 bg-blue-500/10 text-blue-600 dark:text-blue-400",
        icon: Loader2,
      };
    case "device_offline":
      return {
        label: t("devices.state.device_offline"),
        className: "border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400",
        icon: WifiOff,
      };
    case "stale":
      return {
        label: t("devices.state.stale"),
        className: "border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400",
        icon: AlertTriangle,
      };
    case "expired":
      return {
        label: t("devices.state.expired"),
        className: "border-border-subtle bg-surface text-muted",
        icon: Clock,
      };
    default:
      return {
        label: t("devices.state.pending"),
        className: "border-border-subtle bg-surface text-muted",
        icon: CircleDashed,
      };
  }
}

export function StateBadge({ state }: { state: DeviceTaskState }) {
  const { t } = useTranslation();
  const meta = stateMeta(state, t);
  const Icon = meta.icon;
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] ${meta.className}`}
      data-state={state}
    >
      <Icon className={`h-3 w-3 ${state === "executing" ? "animate-spin" : ""}`} />
      {meta.label}
    </span>
  );
}

function formatTimestamp(ts: number | null, locale: string): string {
  if (!ts) return "";
  return new Date(ts * 1000).toLocaleString(locale);
}

/** Tauri command rejections arrive as the serialized AppError object
 * ({kind, message}); String(err) on it yields "[object Object]". */
function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  if (typeof err === "object" && err !== null && "message" in err) {
    const msg = (err as { message: unknown }).message;
    if (typeof msg === "string" && msg) return msg;
  }
  return String(err);
}

function ChannelSetupForm({ onSaved }: { onSaved: () => Promise<void> }) {
  const { t } = useTranslation();
  const [url, setUrl] = useState("");
  const [branch, setBranch] = useState("");
  const [saving, setSaving] = useState(false);

  const save = async () => {
    if (!url.trim()) {
      toast.error(t("devices.channelUrlRequired"));
      return;
    }
    setSaving(true);
    try {
      await api.devicesSetChannelConfig(url.trim(), branch.trim() || undefined);
      toast.success(t("devices.channelSaved"));
      await onSaved();
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="app-panel p-4" data-testid="devices-not-configured">
      <h2 className="app-section-title">{t("devices.channelTitle")}</h2>
      <p className="mb-3 text-[12px] text-muted">{t("devices.channelHint")}</p>
      <div className="flex flex-col gap-2">
        <label className="flex flex-col gap-1">
          <span className="text-[12px] text-secondary">{t("devices.channelUrlLabel")}</span>
          <input
            className="app-input font-mono"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://github.com/user/skills-manager-device-channel.git"
            data-testid="channel-url-input"
          />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-[12px] text-secondary">{t("devices.channelBranchLabel")}</span>
          <input
            className="app-input font-mono"
            value={branch}
            onChange={(e) => setBranch(e.target.value)}
            placeholder="skills-manager-devices"
          />
        </label>
        <button
          type="button"
          className="app-button-primary mt-1 inline-flex h-8 items-center justify-center gap-2 self-start"
          onClick={() => void save()}
          disabled={saving}
          data-testid="channel-save"
        >
          {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <CheckCircle2 className="h-4 w-4" />}
          {saving ? t("devices.saving") : t("devices.saveChannel")}
        </button>
      </div>
    </div>
  );
}

/** Local signing identity + pairing import/export. Exporting hands out
 * public material only; importing trusts a peer key only after the user
 * compares fingerprints and presses approve. */
function IdentityPairingCard() {
  const { t } = useTranslation();
  const [identity, setIdentity] = useState<api.DeviceIdentityStatus | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [exported, setExported] = useState<string | null>(null);
  const [importText, setImportText] = useState("");
  const [preview, setPreview] = useState<api.PairingPreview | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.devicesIdentityGet()
      .then(setIdentity)
      .catch((err) => setLoadError(errorMessage(err)));
  }, []);

  const exportPairing = async () => {
    setBusy(true);
    try {
      const manifest = await api.devicesPairingExport(["command", "receipt", "library_report"]);
      const text = JSON.stringify(manifest, null, 2);
      setExported(text);
      try { await navigator.clipboard.writeText(text); } catch { /* manual copy still works */ }
      toast.success(t("devices.pairingExported"));
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const checkImport = async () => {
    setBusy(true);
    setPreview(null);
    try {
      setPreview(await api.devicesPairingPreview(importText.trim()));
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const approveImport = async () => {
    setBusy(true);
    try {
      const result = await api.devicesPairingApprove(importText.trim());
      toast.success(t("devices.pairingApproved", { device: result.device_id }));
      setPreview(null);
      setImportText("");
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="app-panel p-4" data-testid="device-identity-card">
      <h2 className="app-section-title">{t("devices.identityTitle")}</h2>
      <p className="mb-3 text-[12px] text-muted">{t("devices.identityHint")}</p>
      {loadError ? (
        <p className="text-[13px] text-red-600 dark:text-red-400" data-testid="identity-error">
          {loadError}
        </p>
      ) : !identity ? (
        <div className="flex items-center gap-2 text-[13px] text-muted">
          <Loader2 className="h-4 w-4 animate-spin" />
        </div>
      ) : (
        <>
          <div className="flex flex-wrap gap-x-6 gap-y-1 text-[12px]">
            <span>
              <span className="text-secondary">{t("devices.identityDeviceId")}: </span>
              <span className="font-mono" data-testid="identity-device-id">{identity.device_id}</span>
            </span>
            <span>
              <span className="text-secondary">{t("devices.identityKey")}: </span>
              <span className="font-mono">{identity.key_id}</span>
            </span>
            <span>
              <span className="text-secondary">{t("devices.identityFingerprint")}: </span>
              <span className="font-mono tracking-widest" data-testid="identity-fingerprint">
                {identity.fingerprint}
              </span>
            </span>
          </div>

          <div className="mt-3 flex flex-col gap-2">
            <button
              type="button"
              className="app-button-secondary inline-flex h-8 items-center gap-2 self-start"
              onClick={() => void exportPairing()}
              disabled={busy}
              data-testid="pairing-export"
            >
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
              {t("devices.pairingExport")}
            </button>
            {exported && (
              <>
                <p className="text-[12px] text-muted">{t("devices.pairingExportHint")}</p>
                <textarea
                  className="app-input h-28 font-mono text-[11px]"
                  readOnly
                  value={exported}
                  data-testid="pairing-export-text"
                  onFocus={(e) => e.currentTarget.select()}
                />
              </>
            )}
          </div>

          <div className="mt-4 border-t border-border-subtle pt-3">
            <div className="text-[13px] font-medium">{t("devices.pairingImportTitle")}</div>
            <textarea
              className="app-input mt-2 h-20 font-mono text-[11px]"
              value={importText}
              onChange={(e) => setImportText(e.target.value)}
              placeholder={t("devices.pairingImportPlaceholder")}
              data-testid="pairing-import-text"
            />
            {!preview ? (
              <button
                type="button"
                className="app-button-secondary mt-2 inline-flex h-8 items-center gap-2"
                onClick={() => void checkImport()}
                disabled={busy || !importText.trim()}
                data-testid="pairing-check"
              >
                <CheckCircle2 className="h-4 w-4" />
                {t("devices.pairingPreview")}
              </button>
            ) : (
              <div className="mt-2 rounded-lg border border-border-subtle p-3" data-testid="pairing-preview">
                <p className="text-[12px] text-muted">{t("devices.pairingPreviewIntro")}</p>
                <p className="mt-1 font-mono text-[16px] font-semibold tracking-widest">
                  {preview.fingerprint}
                </p>
                <p className="mt-1 text-[12px]">
                  <span className="text-secondary">{t("devices.identityDeviceId")}: </span>
                  <span className="font-mono">{preview.device_id}</span>
                  <span className="text-secondary"> · {t("devices.pairingPurposes")}: </span>
                  <span className="font-mono">{preview.purposes.join(", ")}</span>
                </p>
                <div className="mt-2 flex gap-2">
                  <button
                    type="button"
                    className="app-button-primary inline-flex h-8 items-center gap-2"
                    onClick={() => void approveImport()}
                    disabled={busy}
                    data-testid="pairing-approve"
                  >
                    <CheckCircle2 className="h-4 w-4" />
                    {t("devices.pairingApprove")}
                  </button>
                  <button
                    type="button"
                    className="app-button-secondary inline-flex h-8 items-center"
                    onClick={() => setPreview(null)}
                    disabled={busy}
                  >
                    {t("devices.pairingCancel")}
                  </button>
                </div>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}

function AddDeviceForm({ onAdded }: { onAdded: () => Promise<void> }) {
  const { t } = useTranslation();
  const [name, setName] = useState("");
  const [platform, setPlatform] = useState("");
  const [adding, setAdding] = useState(false);

  const add = async () => {
    if (!name.trim()) {
      toast.error(t("devices.deviceNameRequired"));
      return;
    }
    setAdding(true);
    try {
      await api.devicesAddDevice(name.trim(), platform.trim() || undefined);
      toast.success(t("devices.deviceAdded"));
      setName("");
      setPlatform("");
      await onAdded();
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setAdding(false);
    }
  };

  return (
    <div className="app-panel-muted flex flex-wrap items-end gap-2 p-4">
      <label className="flex flex-col gap-1">
        <span className="text-[12px] text-secondary">{t("devices.deviceNameLabel")}</span>
        <input
          className="app-input w-56"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="E470C"
          data-testid="add-device-name"
        />
      </label>
      <label className="flex flex-col gap-1">
        <span className="text-[12px] text-secondary">{t("devices.devicePlatformLabel")}</span>
        <input
          className="app-input w-40"
          value={platform}
          onChange={(e) => setPlatform(e.target.value)}
          placeholder="linux"
        />
      </label>
      <button
        type="button"
        className="app-button-secondary inline-flex h-8 items-center gap-2"
        onClick={() => void add()}
        disabled={adding}
        data-testid="add-device-submit"
      >
        {adding ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
        {t("devices.addDevice")}
      </button>
    </div>
  );
}

/** Per-device deploy/undeploy request form. Everything is optional except
 * what the action needs; the backend re-validates all of it before the
 * instruction is published. */
function InstructionForm({ device, onCreated }: { device: DeviceWithStatus; onCreated: () => Promise<void> }) {
  const { t } = useTranslation();
  const [action, setAction] = useState("deploy");
  const [skillUrl, setSkillUrl] = useState("");
  const [skillBranch, setSkillBranch] = useState("");
  const [skillSubpath, setSkillSubpath] = useState("");
  const [skillName, setSkillName] = useState("");
  const [agentKey, setAgentKey] = useState("");
  const [creating, setCreating] = useState(false);
  const instructionHintId = `instruct-hint-${device.id}`;

  const create = async () => {
    setCreating(true);
    try {
      await api.devicesCreateSignedInstruction({
        deviceId: device.id,
        action,
        skillUrl: skillUrl.trim() || undefined,
        skillBranch: skillBranch.trim() || undefined,
        skillSubpath: skillSubpath.trim() || undefined,
        skillName: skillName.trim() || undefined,
        agentKey: agentKey.trim(),
      });
      toast.success(t("devices.instructionCreated"));
      await onCreated();
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setCreating(false);
    }
  };

  return (
    <div className="mt-3 rounded-lg border border-border-subtle p-3" data-testid={`instruct-form-${device.id}`}>
      <div className="app-section-title text-[13px]">{t("devices.instructTitle")}</div>
      <p id={instructionHintId} className="mb-2 text-[12px] text-muted">{t("devices.instructHint")}</p>
      <div className="flex flex-wrap items-end gap-2">
        <label className="flex flex-col gap-1">
          <span className="text-[12px] text-secondary">{t("devices.actionLabel")}</span>
          <select
            className="app-input w-32"
            value={action}
            onChange={(e) => setAction(e.target.value)}
            data-testid={`instruct-action-${device.id}`}
          >
            <option value="deploy">{t("devices.action.deploy")}</option>
            <option value="undeploy">{t("devices.action.undeploy")}</option>
          </select>
        </label>
        {action === "deploy" && (
          <>
            <label className="flex flex-col gap-1">
              <span className="text-[12px] text-secondary">{t("devices.skillUrlLabel")}</span>
              <input
                className="app-input w-72 font-mono"
                value={skillUrl}
                onChange={(e) => setSkillUrl(e.target.value)}
                placeholder="https://github.com/user/skills.git"
                data-testid={`instruct-url-${device.id}`}
              />
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-[12px] text-secondary">{t("devices.skillBranchLabel")}</span>
              <input
                className="app-input w-28 font-mono"
                value={skillBranch}
                onChange={(e) => setSkillBranch(e.target.value)}
                placeholder="main"
              />
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-[12px] text-secondary">{t("devices.skillSubpathLabel")}</span>
              <input
                className="app-input w-48 font-mono"
                value={skillSubpath}
                onChange={(e) => setSkillSubpath(e.target.value)}
                placeholder="skills/demo"
              />
            </label>
          </>
        )}
        <label className="flex flex-col gap-1">
          <span className="text-[12px] text-secondary">{t("devices.skillNameLabel")}</span>
          <input
            className="app-input w-40 font-mono"
            value={skillName}
            onChange={(e) => setSkillName(e.target.value)}
            placeholder="dual-machine-pilot"
            data-testid={`instruct-name-${device.id}`}
          />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-[12px] text-secondary">{t("devices.agentKeyLabel")}</span>
          <input
            className="app-input w-32 font-mono"
            value={agentKey}
            onChange={(e) => setAgentKey(e.target.value)}
            placeholder="openclaw"
            data-testid={`instruct-agent-${device.id}`}
          />
        </label>
        <button
          type="button"
          className="app-button-primary inline-flex h-8 items-center gap-2"
          onClick={() => void create()}
          disabled={creating}
          aria-describedby={instructionHintId}
          data-testid={`instruct-submit-${device.id}`}
        >
          {creating ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
          {t("devices.createInstruction")}
        </button>
      </div>
    </div>
  );
}

export function Devices() {
  const { t, i18n } = useTranslation();
  const locale = i18n.language;

  const [page, setPage] = useState<api.DevicesPage | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      setPage(await api.devicesGetPage());
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const refresh = async () => {
    setRefreshing(true);
    setError(null);
    try {
      setPage(await api.devicesRefreshChannel());
    } catch (err) {
      setError(`${t("devices.refreshFailed")} ${errorMessage(err)}`);
    } finally {
      setRefreshing(false);
    }
  };

  const deviceName = (deviceId: string): string =>
    page?.devices.find((d) => d.id === deviceId)?.name ?? deviceId;

  return (
    <div className="app-page">
      <div className="app-page-header">
        <div>
          <h1 className="app-page-title">{t("devices.manageTitle")}</h1>
          <p className="app-page-subtitle">{t("devices.subtitle")}</p>
        </div>
        <button
          type="button"
          className="app-button-secondary inline-flex items-center gap-2"
          onClick={() => void refresh()}
          disabled={refreshing || !page?.channel.configured}
          data-testid="devices-refresh"
        >
          {refreshing ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <RefreshCw className="h-4 w-4" />
          )}
          {t("devices.refresh")}
        </button>
      </div>

      <RepositorySources devices={page?.devices ?? []} />
      <LocalInventoryPreview />
      <IdentityPairingCard />

      {error && (
        <div
          className="rounded-xl border border-red-500/25 bg-red-500/10 px-4 py-3 text-[13px] text-red-600 dark:text-red-400"
          data-testid="devices-error"
          role="alert"
        >
          {error}
        </div>
      )}

      {loading ? (
        <div className="flex items-center gap-2 p-6 text-[13px] text-muted">
          <Loader2 className="h-4 w-4 animate-spin" />
          {t("devices.loading")}
        </div>
      ) : !page ? null : (
        <div className="flex flex-col gap-4">
          {!page.channel.configured && (
            <ChannelSetupForm onSaved={load} />
          )}

          {page.channel.configured && (
            <>
              <div className="app-panel-muted flex flex-wrap items-center gap-x-4 gap-y-1 px-4 py-3 text-[12px] text-muted">
                <span className="inline-flex items-center gap-1.5">
                  <Monitor className="h-3.5 w-3.5" />
                  {page.channel.url_redacted}
                </span>
                <span>{page.channel.branch}</span>
                <span>
                  {t("devices.thisDevice")}: {page.channel.local_device_name} ({page.channel.local_device_id})
                </span>
              </div>

              <div
                className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-[13px] text-amber-700 dark:text-amber-300"
                data-testid="device-snapshot-notice"
                role={page.snapshot_warnings?.length ? "alert" : "status"}
              >
                <p>{t("devices.cachedProjectionNotice")}</p>
                {page.snapshot_warnings == null ? (
                  <p className="mt-1">{t("devices.channelNotChecked")}</p>
                ) : page.snapshot_warnings.length > 0 ? (
                  <>
                    <p className="mt-1 font-medium">{t("devices.channelIncomplete")}</p>
                    <ul className="mt-1 list-inside list-disc">
                      {page.snapshot_warnings.map((warning, index) => <li key={index}>{warning}</li>)}
                    </ul>
                  </>
                ) : (
                  <p className="mt-1">{t("devices.channelNoWarnings")}</p>
                )}
              </div>

              <AddDeviceForm onAdded={load} />

              {page.devices.length === 0 ? (
                <div className="app-panel p-6 text-[13px] text-muted" data-testid="devices-empty">
                  {t("devices.currentNoDevices")}
                </div>
              ) : (
                page.devices.map((device) => (
                  <div key={device.id} className="app-panel p-4" data-testid={`device-${device.id}`}>
                    <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                      <span className="text-[14px] font-medium">{device.name}</span>
                      {device.platform && (
                        <span className="app-badge text-[11px]">{device.platform}</span>
                      )}
                      <span
                        className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] ${
                          device.online
                            ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                            : "border-border-subtle bg-surface text-muted"
                        }`}
                        data-testid={`device-online-${device.online}`}
                      >
                        {device.online ? t("devices.online") : t("devices.offline")}
                      </span>
                      <span className="text-[12px] text-muted">
                        {device.last_seen_at
                          ? t("devices.lastSeen", {
                              time: formatTimestamp(device.last_seen_at, locale),
                            })
                          : t("devices.neverReported")}
                      </span>
                    </div>

                    {device.skill_records.length === 0 ? (
                      <p className="mt-3 text-[12px] text-muted">{t("devices.currentNoSkillRecords")}</p>
                    ) : (
                      <div className="mt-3 flex flex-col gap-2">
                        {Object.entries(
                          device.skill_records.reduce<Record<string, api.DeviceSkillRecord[]>>(
                            (acc, record) => {
                              (acc[record.agent_key] ??= []).push(record);
                              return acc;
                            },
                            {},
                          ),
                        ).map(([agentKey, records]) => (
                          <div key={agentKey} className="rounded-lg border border-border-subtle px-3 py-2">
                            <div className="text-[12px] font-medium">{agentKey}</div>
                            <ul className="mt-1 flex flex-col gap-0.5" aria-label={agentKey}>
                              {records.map((record) => (
                                <li
                                  key={`${agentKey}:${record.skill_name}`}
                                  className="flex flex-wrap items-center gap-x-2 text-[13px]"
                                >
                                  <span>{record.skill_name}</span>
                                  {record.deployed_at && (
                                    <span className="text-[12px] text-muted">
                                      {formatTimestamp(record.deployed_at, locale)}
                                    </span>
                                  )}
                                </li>
                              ))}
                            </ul>
                          </div>
                        ))}
                      </div>
                    )}

                    <InstructionForm device={device} onCreated={load} />
                  </div>
                ))
              )}

              <div className="app-panel p-4">
                <h2 className="app-section-title">{t("devices.instructionsTitle")}</h2>
                <p className="mb-3 text-[12px] text-muted">{t("devices.dataNotice")}</p>
                {page.instructions.length === 0 ? (
                  <p className="text-[13px] text-muted" data-testid="instructions-empty">
                    {t("devices.currentNoInstructions")}
                  </p>
                ) : (
                  <ul className="flex flex-col gap-2" data-testid="instructions-list">
                    {page.instructions.map((inst) => (
                      <li
                        key={inst.id}
                        className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-lg border border-border-subtle px-3 py-2"
                        data-testid={`instruction-${inst.id}`}
                      >
                        <StateBadge state={inst.state} />
                        <span className="text-[13px] font-medium">
                          {inst.skill_name ?? inst.id}
                        </span>
                        <span className="app-badge text-[11px]">
                          {t(`devices.action.${inst.action}`)}
                        </span>
                        <span className="text-[12px] text-muted">{deviceName(inst.device_id)}</span>
                        <span className="text-[12px] text-muted">{inst.agent_key}</span>
                        {inst.receipt_detail && (
                          <span className="text-[12px] text-muted">{inst.receipt_detail}</span>
                        )}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}
