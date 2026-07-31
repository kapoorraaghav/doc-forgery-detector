# DocForge — Document Forgery Detector

Hackathon-ready forgery detection tool. Three forensic passes on any uploaded
image (ID, certificate, invoice):

1. **Error Level Analysis (ELA)** — recompresses at known JPEG quality, diffs
   against original to surface regions edited after the last save.
2. **EXIF metadata check** — flags editing-software fingerprints
   (Photoshop/GIMP/etc.) and timestamp inconsistencies.
3. **Copy-move detection** — ORB keypoint matching to catch duplicated
   regions (e.g. a copy-pasted signature or stamp).

Scores are combined into a weighted composite (0–100) with a verdict:
`LIKELY AUTHENTIC` / `SUSPICIOUS` / `LIKELY FORGED`.

## Run it

    pip install -r requirements.txt
    python app.py

Then open http://localhost:5000

## Extend it (ideas for the next hours)
- Swap the rule-based scoring for a trained CNN classifier on the CASIA v2
  tampering dataset — forensics.py already returns the same interface, so
  you can slot in `model.predict()` for `ela_score`/`copy_move_score`.
- Add OCR-based font/spacing consistency checks (Tesseract) for scanned text
  documents like marksheets.
- Add PDF support via PyMuPDF (render pages to images, reuse forensics.py).
- Batch mode / API endpoint (`POST /api/analyze`) returning JSON for demo
  integrations.

## Known limitations (say this out loud in your demo — judges respect it)
- ELA is JPEG-artifact based; PNGs with no compression history give weaker
  signal (metadata + copy-move still work).
- Copy-move detection can false-positive on documents with genuinely
  repetitive textures (e.g. dense line patterns) — the distance/ratio
  thresholds in `detect_copy_move()` are tunable.
- This is heuristic evidence, not a certified forensic tool.
