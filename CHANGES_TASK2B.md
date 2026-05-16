# Task 2B — Fix: swap primary/secondary button hierarchy in AI Fit status band

## What changed

### `app.js` — line ~3959

**Before:**
```html
<button class="aifit-rescan-btn" onclick="reuploadResume()" … style="background:transparent;border:1px solid var(--border2);color:var(--text2);margin-right:6px">Upload new résumé</button>
<button class="aifit-rescan-btn" onclick="rescanAIFit()">Re-scan</button>
```

**After:**
```html
<button class="aifit-upload-btn" onclick="reuploadResume()" title="Upload a different résumé">Upload new résumé</button>
<button class="aifit-rescan-btn" onclick="rescanAIFit()">Re-scan</button>
```

- "Upload new résumé" is now the first (left) button and uses the new `.aifit-upload-btn` class.
- Inline `style=""` is removed; styling lives in CSS.
- "Re-scan" remains second (right); its class is unchanged but its CSS is now secondary.

### `styles.css` — after `.aifit-summary-date`

**Added** `.aifit-upload-btn` (primary):
- `background:#fff` — white fill on the dark-green strip; high contrast, clearly the lead action.
- `color:var(--accent2)` — dark green text pairs with the strip background.
- `min-height:44px` — meets mobile tap-target requirement (Task 7 prep).

**Restyled** `.aifit-rescan-btn` (now secondary):
- `background:transparent; border:1px solid rgba(255,255,255,.3); color:rgba(255,255,255,.7)` — outlined ghost style, visually receded.
- Hover restores `rgba(255,255,255,.1)` fill so it still has clear hover feedback.
- `min-height:44px` added here too.

## What was NOT touched

- Scan counter logic (`_scanCount`, `SCAN_QUOTA_CLIENT`, live Supabase fetch) — Task 2 unchanged.
- `reuploadResume()` and `rescanAIFit()` function bodies — only styling was changed.
- Persistence / `loadAndRenderLastScan` — Task 1/1B unchanged.

## How to verify visually

1. Open the app and complete a scan (or load a previously saved scan).
2. The status band should show **two buttons on the right side**:
   - LEFT: "Upload new résumé" — **white filled**, dark green text. Prominent.
   - RIGHT: "Re-scan" — **outlined ghost**, white text. Receded.
3. Clicking "Upload new résumé" should:
   - Hide the results view.
   - Show the upload zone.
   - Immediately open the OS file picker.
4. Clicking "Re-scan" should re-run the analysis on the existing résumé (unchanged behavior).
5. On a narrow viewport both buttons should still have ≥44px tap height.
