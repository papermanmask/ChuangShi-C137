# 创世 C137 · 长篇小说创作引擎与可视化工作台

本地工程 `创世-C137` 的公开同步版本，包含创作工作台（Python HTTP 服务 + 单页前端）、
创作引擎脚本、前端依赖库与项目文档。最近一轮更新为世界树画布（层级带、状态着色、
双击直达、检查器定位、方向键平移）与流向光点实时独立动画，详见
`创作界面与可视化_规划_v1.md` §11.21。

## 目录
| 路径 | 内容 |
|---|---|
| `app/` | 服务端 `app.py`、单页工作台 `workbench.html`、审校/账本/加密模块、SOP 规则与配置 |
| `app/vendor/` | 已本地化的前端依赖：Chart.js、Cytoscape、ECharts、Three.js（含 LICENSE） |
| `engine/` | 引擎侧脚本、代理与仪表盘、`package.json`（`node_modules` 未随仓库分发） |
| `project/inkos.json` | 项目配置模板（不含密钥与书本数据） |
| `*.md` | 界面规范、重构方案、部署说明、可视化规划 |

## 启动
1. `cd app && python app.py`（Python 3.13；端口取 `app/config.json`，默认 8787）
2. 浏览器打开 `http://127.0.0.1:8787/workbench.html`
3. 首次使用运行根目录 `配置密钥.bat` 生成 `app/key.enc`（Windows DPAPI 加密）；
   需要引擎能力时在 `engine/` 下执行 `npm install`。

## 未随仓库分发的内容（本地保留）
- **凭据**：`app/key.enc`、`engine/.inkos_key.enc`、`project/.env`、
  `engine/dream-crystal/.env` —— 本仓库不含任何密钥。
- **创作数据**：`project/books/` 下的书本正文、状态、记忆库与快照。
- **运行期产物**：`logs/`、`usage.json`、`usage_ledger.json`、`*.bak_*` 本地备份。
- **大体积素材**：`app/assets/`（3D 行星贴图与神龙 GLB，约 58MB）。
  仓库中的 3D 星球展示功能需在本地补齐该目录后可用；其余功能不依赖它。
- **运行时**：`runtime/`（Node/Python 便携运行时）、`engine/node_modules/`。

公开仓库仅包含代码、配置模板与文档。未声明开源许可证。
