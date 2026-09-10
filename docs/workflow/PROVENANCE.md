# Workflow diagram provenance

This authored guide describes Open-Detective runtime revision [`39ca3a19cc17fc454c38de2709866fccd3784956`](https://github.com/kindsusu/Open-Detective/tree/39ca3a19cc17fc454c38de2709866fccd3784956). It is not a live investigation trace or an automatic orchestration pipeline. English is the authored language; Korean guidance is maintained in README.ko.md.

## Renderer and reproduction

The JSON is rendered with Archify `2.17.0-dev.1`, pinned to `10722002bb8777ecb639d93c49586fae4adf3ae4`, using the existing local checkout. No new dependency or global skill was installed.

```bash
node bin/archify.mjs deliver workflow /path/to/open-detective.workflow.json /path/to/output.html --quality showcase --json
```

The generated delivery passed all nine checks, with zero composition errors or warnings. The published HTML retains the reviewed existing viewer styles, dark-startup script, dark fallback and selected-theme SVG export. Preserve these theme changes when regenerating: the vanilla renderer does not reproduce them. Run `python docs/workflow/check_dark_theme.py` to check required markers. PNG and SVG are exported using the actual viewer's Export controls in dark mode.

## Current content and visual review

Optional branches now show scoped code-search metadata, private location export, scoped static tracing, and profiling of already captured local bytes. File locations do not fetch content. Human ownership/scope approval and evidence review remain separate. The main sequence and independently authorized local-forensics branch remain present. Node colors are renderer categories, not claims of deployed services or autonomous agents.

The complete exported PNG was visually inspected. It requires vertical scrolling; first-screen containment is not claimed. Default dark under a light OS and explicit URL/storage light overrides are tested separately. VALIDATION.json records current artifact hashes and actual checks, not old results attributed to new files.

## Attribution

Archify viewer code remains under MIT ([ARCHIFY-LICENSE.txt](ARCHIFY-LICENSE.txt)); the embedded JetBrains Mono font remains under SIL OFL ([JetBrainsMono-OFL.txt](JetBrainsMono-OFL.txt)).
