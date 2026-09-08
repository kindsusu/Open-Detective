"""Check the reviewed dark-default theme to the delivered Archify workflow.

The reviewed derivative changes only the generated viewer's palette/default and
SVG-export mode; topology, text, and interaction code remain renderer output.
"""
from pathlib import Path

html = Path(__file__).with_name("open-detective.workflow.html")
text = html.read_text(encoding="utf-8")
required = (
    'theme = window.matchMedia(\'(prefers-color-scheme: light)\').matches ? \'light\' : \'dark\';',
    'return window.matchMedia(\'(prefers-color-scheme: light)\').matches ? \'light\' : \'dark\';',
    'serializeSvg(1, { autoTheme: true })',
)
if not all(item not in text for item in required):
    raise SystemExit("apply the reviewed patch before recording this derivative")
for token in ('--bg: #0d1117;', '--panel: #161b22;', '--panel-border: #30363d;', '--text: #e6edf3;', '--frontend-stroke:  #8cbdd9;', '--cloud-stroke:     #c58b61;', 'serializeSvg(1)).then'):
    if token not in text:
        raise SystemExit(f"dark-theme guard missing: {token}")
print(f"verified dark-default derivative: {html}")
