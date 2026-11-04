import { useTranslation } from "react-i18next";
import { Loader2, RefreshCw, Monitor } from "lucide-react";
import { cn } from "../utils";
import { useNavigate } from "react-router-dom";
import type { DeviceInstructionRow, DeviceWithStatus } from "../lib/tauri";
import { StateBadge } from "../views/Devices";

function formatTimestamp(ts: number | null, locale: string): string {
  if (!ts) return "";
  return new Date(ts * 1000).toLocaleString(locale);
}

/** The remote-device form of the library page: what the device last
 * reported about its own agents, plus its deployment requests and
 * outcomes. Strictly read-only — "deployed" appears only when the device
 * itself reported it (docs/devices.md). */
export function RemoteDeviceLibrary({
  device,
  instructions,
  loading,
  onRefresh,
}: {
  device: DeviceWithStatus;
  instructions: DeviceInstructionRow[];
  loading: boolean;
  onRefresh: () => void;
}) {
  const { t, i18n } = useTranslation();
  const locale = i18n.language;
  const navigate = useNavigate();
  const deviceInstructions = instructions.filter((inst) => inst.device_id === device.id);

  return (
    <div className="app-page" data-testid="remote-library">
      <div className="app-page-header">
        <div>
          <h1 className="app-page-title">
            {t("mySkills.remoteTitle", { name: device.name })}
          </h1>
          <p className="app-page-subtitle">{t("mySkills.remoteSubtitle")}</p>
        </div>
        <button
          type="button"
          className="app-button-secondary inline-flex items-center gap-2"
          onClick={onRefresh}
          disabled={loading}
          data-testid="remote-refresh"
        >
          {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
          {t("devices.refresh")}
        </button>
      </div>

      <div className="app-panel p-4" data-testid={`remote-device-${device.id}`}>
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <span className="inline-flex items-center gap-1.5 text-[14px] font-medium">
            <Monitor className="h-4 w-4 text-muted" />
            {device.name}
          </span>
          {device.platform && <span className="app-badge text-[11px]">{device.platform}</span>}
          <span
            className={cn(
              "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px]",
              device.online
                ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                : "border-border-subtle bg-surface text-muted"
            )}
            data-testid={`remote-online-${device.online}`}
          >
            {device.online ? t("devices.online") : t("devices.offline")}
          </span>
          <span className="text-[12px] text-muted">
            {device.last_seen_at
              ? t("devices.lastSeen", { time: formatTimestamp(device.last_seen_at, locale) })
              : t("devices.neverReported")}
          </span>
        </div>

        {device.skill_records.length === 0 ? (
          <p className="mt-3 text-[13px] text-muted" data-testid="remote-no-skills">
            {t("devices.noSkillRecords")}
          </p>
        ) : (
          <div className="mt-3 flex flex-col gap-2">
            {Object.entries(
              device.skill_records.reduce<Record<string, typeof device.skill_records>>(
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
      </div>

      <div className="app-panel p-4">
        <h2 className="app-section-title">{t("devices.instructionsTitle")}</h2>
        <p className="mb-3 text-[12px] text-muted">{t("devices.dataNotice")}</p>
        {deviceInstructions.length === 0 ? (
          <p className="text-[13px] text-muted">{t("devices.noInstructions")}</p>
        ) : (
          <ul className="flex flex-col gap-2">
            {deviceInstructions.map((inst) => (
              <li
                key={inst.id}
                className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-lg border border-border-subtle px-3 py-2"
              >
                <StateBadge state={inst.state} />
                <span className="text-[13px] font-medium">{inst.skill_name ?? inst.id}</span>
                <span className="app-badge text-[11px]">{t(`devices.action.${inst.action}`)}</span>
                {inst.receipt_detail && (
                  <span className="text-[12px] text-muted">{inst.receipt_detail}</span>
                )}
              </li>
            ))}
          </ul>
        )}
        <div className="mt-3">
          <button
            type="button"
            className="text-[12px] text-accent hover:underline"
            onClick={() => navigate("/devices")}
          >
            {t("mySkills.remoteManageLink")}
          </button>
        </div>
      </div>
    </div>
  );
}
