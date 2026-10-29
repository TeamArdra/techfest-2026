# Report figures rendered from Mermaid source

| Report figure | Source | Rendered |
|---|---|---|
| Figure 3, live receive-only architecture (report §3, §9) | `fig3_live_receive_only_architecture.mmd` | `.png` (2x scale), `.svg` |
| Figure 4, methodology and workflow (report §4) | `fig4_methodology_workflow.mmd` | `.png` (2x scale), `.svg` |

The `.mmd` files are the diagram blocks of `docs/stage2_report_draft.md` §3 and §4 (Figure 3 only changed from `flowchart LR` to `flowchart TB` so it is
legible at page width). They describe the code path as built; they add no result and no measurement.

Rendered 2026-10-29 with `@mermaid-js/mermaid-cli` 11.4.2, installed in a scratch directory outside the repository (the repo has no Mermaid toolchain), using the
installed Chrome (`PUPPETEER_SKIP_DOWNLOAD=1`, puppeteer config `{"executablePath": "<chrome.exe>", "args": ["--no-sandbox"]}`):

```
mmdc -p <puppeteer-config.json> -i fig3_live_receive_only_architecture.mmd -o fig3_live_receive_only_architecture.png -s 2 -b white
mmdc -p <puppeteer-config.json> -i fig3_live_receive_only_architecture.mmd -o fig3_live_receive_only_architecture.svg -b white
```
(same for `fig4_...`). The Stage-1 sources in `docs/diagrams/*.mmd` are **not** rendered; the report cites them only as source.
