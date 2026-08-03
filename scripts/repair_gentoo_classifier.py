#!/usr/bin/env python3
from pathlib import Path

path = Path("scripts/inventory_gentoo_ebuild_shard.py")
text = path.read_text(encoding="utf-8")

phase = '    if FUNCTION_RE.search(text):\n        dynamic.append("phase-functions")\n'
if text.count(phase) != 1:
    raise SystemExit("phase-function block differs")
text = text.replace(phase, "")

manifest = '        if len(fields) < 6 or len(fields) % 2 != 0:\n'
if text.count(manifest) != 1:
    raise SystemExit("Manifest pair condition differs")
text = text.replace(
    manifest,
    '        if len(fields) < 5 or (len(fields) - 3) % 2 != 0:\n',
)

start = text.index("def static_sources(value: str) -> list[dict[str, Any]]:\n")
end = text.index("\ndef read_blob(", start)
replacement = '''def static_sources(value: str) -> list[dict[str, Any]]:
    words = split_shell_words(value)
    sources: list[dict[str, Any]] = []
    redirect_target = False
    for word in words:
        if redirect_target:
            if not word or "/" in word or "\\\\" in word or word in {".", ".."}:
                raise GentooError("SRC_URI redirect target is not a safe filename")
            sources[-1]["filename"] = word
            redirect_target = False
            continue
        if word == "->":
            if not sources:
                raise GentooError("SRC_URI redirect has no source")
            redirect_target = True
            continue
        if not word.startswith("https://") or any(character.isspace() for character in word):
            raise GentooError("SRC_URI contains a non-HTTPS or dynamic source")
        filename = word.rsplit("/", 1)[-1]
        if not filename:
            raise GentooError("SRC_URI source has no filename")
        sources.append({"url": word, "filename": filename})
    if redirect_target:
        raise GentooError("SRC_URI redirect has no target")
    return sources
'''
text = text[:start] + replacement + text[end:]
path.write_text(text, encoding="utf-8")
