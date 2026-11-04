import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { Check, FolderPlus, Pencil, Plus, Trash2, X } from "lucide-react";
import { cn } from "../utils";
import * as api from "../lib/tauri";
import type { LibraryLayer, ManagedSkill } from "../lib/tauri";

function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  if (typeof err === "object" && err !== null && "message" in err) {
    const msg = (err as { message: unknown }).message;
    if (typeof msg === "string" && msg) return msg;
  }
  return String(err);
}

const ROOT_KEY = "__root__";
const inputCls =
  "h-8 w-full rounded-lg border border-border-subtle bg-background px-2.5 text-[13px] text-primary outline-none focus:border-accent-border";

/** Moves one skill into a layer (or back to the library root). */
export function LayerMoveDialog({
  open,
  skill,
  layers,
  currentLayer,
  onClose,
  onMoved,
}: {
  open: boolean;
  skill: ManagedSkill | null;
  layers: LibraryLayer[];
  currentLayer: string | null;
  onClose: () => void;
  onMoved: () => void;
}) {
  const { t } = useTranslation();
  const [selected, setSelected] = useState<string>(ROOT_KEY);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (open) {
      setSelected(currentLayer ?? ROOT_KEY);
    }
  }, [open, currentLayer]);

  if (!open || !skill) return null;

  const confirm = async () => {
    setBusy(true);
    try {
      await api.librarySkillMove(skill.id, selected === ROOT_KEY ? undefined : selected);
      toast.success(t("mySkills.layerDialog.moved"));
      onMoved();
      onClose();
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />
      <div className="relative bg-surface border border-border rounded-xl w-full max-w-[380px] p-5 shadow-2xl">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-[13px] font-semibold text-primary">
            {t("mySkills.layerDialog.moveTitle", { name: skill.name })}
          </h2>
          <button onClick={onClose} className="text-muted hover:text-secondary p-1 rounded-md transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="space-y-1 mb-3">
          {[{ key: ROOT_KEY, label: t("mySkills.layerDialog.root") }, ...layers.map((l) => ({ key: l.name, label: l.name }))].map(
            (option) => (
              <button
                key={option.key}
                type="button"
                onClick={() => setSelected(option.key)}
                className={cn(
                  "flex w-full items-center justify-between rounded-lg px-3 py-2 text-[13px] transition-colors",
                  selected === option.key
                    ? "bg-accent-bg text-primary"
                    : "text-secondary hover:bg-surface-hover"
                )}
              >
                {option.label}
                {selected === option.key && <Check className="h-3.5 w-3.5 text-accent" />}
              </button>
            ),
          )}
        </div>
        <button
          type="button"
          className="app-button-primary inline-flex h-8 items-center gap-1.5"
          onClick={() => void confirm()}
          disabled={busy}
        >
          {t("mySkills.layerDialog.confirm")}
        </button>
      </div>
    </div>
  );
}

/** Create / rename / delete layers. Self-contained: talks to the backend
 * directly and reports changes through `onChanged`. */
export function LayerManageDialog({
  open,
  layers,
  onClose,
  onChanged,
}: {
  open: boolean;
  layers: LibraryLayer[];
  onClose: () => void;
  onChanged: () => void;
}) {
  const { t } = useTranslation();
  const [newName, setNewName] = useState("");
  const [renaming, setRenaming] = useState<string | null>(null);
  const [renameValue, setRenameValue] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (open) {
      setNewName("");
      setRenaming(null);
    }
  }, [open]);

  if (!open) return null;

  const run = async (action: () => Promise<void>) => {
    setBusy(true);
    try {
      await action();
      onChanged();
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />
      <div className="relative bg-surface border border-border rounded-xl w-full max-w-[420px] p-5 shadow-2xl">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-[13px] font-semibold text-primary">{t("mySkills.layerManage.title")}</h2>
          <button onClick={onClose} className="text-muted hover:text-secondary p-1 rounded-md transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="space-y-2 mb-4 max-h-[260px] overflow-y-auto">
          {layers.length === 0 && <p className="text-[13px] text-muted">{t("mySkills.layerManage.empty")}</p>}
          {layers.map((layer) => (
            <div key={layer.name} className="flex items-center gap-2 rounded-lg border border-border-subtle px-3 py-2">
              {renaming === layer.name ? (
                <>
                  <input
                    className={inputCls}
                    value={renameValue}
                    autoFocus
                    onChange={(e) => setRenameValue(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" && renameValue.trim() && renameValue.trim() !== layer.name) {
                        void run(async () => {
                          await api.libraryLayerRename(layer.name, renameValue.trim());
                          toast.success(t("mySkills.layerManage.renamed"));
                        });
                        setRenaming(null);
                      }
                      if (e.key === "Escape") setRenaming(null);
                    }}
                  />
                  <button
                    onClick={() => setRenaming(null)}
                    className="text-muted hover:text-secondary p-1 rounded-md"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                </>
              ) : (
                <>
                  <span className="flex-1 truncate text-[13px] text-primary">{layer.name}</span>
                  <span className="text-[12px] text-muted">{layer.skill_count}</span>
                  <button
                    onClick={() => {
                      setRenaming(layer.name);
                      setRenameValue(layer.name);
                    }}
                    disabled={busy}
                    title={t("common.edit")}
                    className="text-muted hover:text-secondary p-1 rounded-md transition-colors"
                  >
                    <Pencil className="w-3.5 h-3.5" />
                  </button>
                  <button
                    onClick={() =>
                      void run(async () => {
                        await api.libraryLayerDelete(layer.name);
                        toast.success(t("mySkills.layerManage.deleted"));
                      })
                    }
                    disabled={busy}
                    title={t("common.delete")}
                    className="text-muted hover:text-red-500 p-1 rounded-md transition-colors"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </>
              )}
            </div>
          ))}
        </div>

        <div className="flex items-center gap-2">
          <input
            className={inputCls}
            placeholder={t("mySkills.layerManage.placeholder")}
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && newName.trim()) {
                void run(async () => {
                  await api.libraryLayerCreate(newName.trim());
                  toast.success(t("mySkills.layerManage.created"));
                  setNewName("");
                });
              }
            }}
          />
          <button
            type="button"
            className="app-button-secondary inline-flex h-8 shrink-0 items-center gap-1.5"
            disabled={busy || !newName.trim()}
            onClick={() =>
              void run(async () => {
                await api.libraryLayerCreate(newName.trim());
                toast.success(t("mySkills.layerManage.created"));
                setNewName("");
              })
            }
          >
            <FolderPlus className="h-4 w-4" />
            {t("mySkills.layerManage.create")}
          </button>
        </div>
      </div>
    </div>
  );
}

/** First-use suggestion: preset the two layer names the user asked for
 * (本机 / E470C). One click creates both; dismissible. */
export function LayerSuggestBanner({
  visible,
  onCreateBoth,
  onDismiss,
}: {
  visible: boolean;
  onCreateBoth: () => void;
  onDismiss: () => void;
}) {
  const { t } = useTranslation();
  const [busy, setBusy] = useState(false);
  if (!visible) return null;

  const create = async () => {
    setBusy(true);
    try {
      await api.libraryLayerCreate(t("mySkills.layerSuggest.localName"));
      await api.libraryLayerCreate(t("mySkills.layerSuggest.remoteName"));
      onCreateBoth();
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      className="rounded-xl border border-accent-border bg-accent-bg px-4 py-3 mb-3 flex flex-wrap items-center gap-x-3 gap-y-2"
      data-testid="layer-suggest-banner"
    >
      <div className="flex-1 min-w-[200px]">
        <p className="text-[13px] text-primary">{t("mySkills.layerSuggest.title")}</p>
        <p className="text-[12px] text-muted">{t("mySkills.layerSuggest.hint")}</p>
      </div>
      <button
        type="button"
        className="app-button-primary inline-flex h-8 items-center gap-1.5"
        onClick={() => void create()}
        disabled={busy}
      >
        <Plus className="h-4 w-4" />
        {busy ? t("mySkills.layerDialog.working") : t("mySkills.layerSuggest.createBoth")}
      </button>
      <button
        type="button"
        className="text-[12px] text-muted hover:text-secondary px-2 py-1 rounded-md transition-colors"
        onClick={onDismiss}
      >
        {t("mySkills.layerSuggest.dismiss")}
      </button>
    </div>
  );
}
