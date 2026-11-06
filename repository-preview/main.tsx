import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import { RepositorySources } from "../src/components/RepositorySources";
import zh from "../src/i18n/zh.json";
import "../src/index.css";

await i18n.use(initReactI18next).init({
  resources: { zh: { translation: zh } }, lng: "zh",
  interpolation: { escapeValue: false },
});
createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <main className="h-full overflow-auto p-6">
      <div className="app-page app-page-narrow">
        <header className="app-page-header">
          <h1 className="app-page-title">两个 Git 仓库 · 只读预览</h1>
          <p className="app-page-subtitle">仅查看你手动添加的仓库中已提交的技能目录；不会显示设备实时状态、更新或部署技能。</p>
          <p className="app-page-subtitle">仓库配置和最近成功清单保存在此电脑的独立预览数据目录；访问私有仓库依赖本机 Git / SSH 配置，请勿在网址中填写密码或令牌。</p>
        </header>
        <RepositorySources devices={[]} />
      </div>
    </main>
  </StrictMode>,
);
