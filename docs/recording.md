# Session recording

Record the whole session to a single video file, automatically, for every
persona — so what the agent did can be reviewed after the fact.

Recording starts when the server starts and finalizes on shutdown, including on a
kill-switch trip. The agent cannot turn it off: the `Recording` tool exposes only
`status` and `mark`.

- [Enabling it](#enabling-it)
- [Codecs and ffmpeg](#codecs-and-ffmpeg)
- [Timeline markers](#timeline-markers)
- [Output and housekeeping](#output-and-housekeeping)

---

## Enabling it

Recording is a policy setting, not a flag — it is part of the transparency
guarantee, so it lives with the rest of it:

```jsonc
"transparency": {
  "recording_dir": "C:\\ProgramData\\windows-mcp\\recordings"
}
```

Frame rate and codec *are* flags, because they are performance tuning rather than
policy:

```powershell
.\windows-mcp-server.exe stdio --policy-config policy.json --record-codec h265 --record-fps 4
```

| Flag | Default | Notes |
|---|---|---|
| `--record-fps` | `4` | 4 is usually plenty for UI work; higher costs disk and CPU |
| `--record-codec` | `h264` | `h264`, `h265` or `mjpeg` |

Frames are downscaled to 1280px wide by default to keep files manageable.

---

## Codecs and ffmpeg

**`h264` and `h265` need ffmpeg on `PATH`.** They use temporal compression, so
files are far smaller — H.265 roughly half the size of H.264.

**Without ffmpeg, recording falls back to MJPEG-AVI**, a pure-Go writer with no
dependency. It always works, but every frame is an independent JPEG, so files are
much larger. The fallback is logged — `recorder: ffmpeg not found, falling back
to MJPEG (larger files)` — but at the first captured frame rather than at
startup, so it is easy to miss in a long log.

That fallback is the thing to check: a deployment that assumed H.265 and got
MJPEG will fill a disk faster than expected.

### Installing ffmpeg

```powershell
winget install Gyan.FFmpeg
# or
choco install ffmpeg
```

Then open a new shell so `PATH` is refreshed, and confirm:

```powershell
ffmpeg -version
```

### Confirming which codec you actually got

The startup log names the writer, and the output file's extension follows it —
`.mp4` for h264/h265, `.avi` for MJPEG. Or ask the running server:

```jsonc
{"mode": "status"}
```

```
Session recording: ON
File: C:\ProgramData\windows-mcp\recordings\session-20260731-142230.mp4
Markers: …\session-20260731-142230.jsonl
Frames: 1284 @ 4 fps
Duration: 321.0s
```

Force the dependency-free writer when you would rather not rely on ffmpeg being
present:

```powershell
--record-codec mjpeg
```

---

## Timeline markers

The `Recording` tool is in the `screen` toolset, so every persona has it. Marking
each step aligns the video with what the agent was doing:

```jsonc
{"mode": "mark", "label": "signed in"}
```

Markers land in a sidecar `.jsonl` next to the video. For journey testing, mark
at each step — it turns a 5-minute video into something you can navigate:

```
Snapshot
Invoke  {name:"Sign in"}
WaitFor {condition:active_window, window_name:"Inbox"}
Recording {mode:mark, label:"signed in"}
Assert  {condition:text_present, text:"Welcome"}
```

`mark` on a session that is not being recorded is a no-op that says so, rather
than an error — a journey script works the same whether recording is on or not.

---

## Output and housekeeping

Each session produces two files in `recording_dir`:

```
session-<timestamp>.mp4     (or .avi for mjpeg)
session-<timestamp>.jsonl   markers
```

### Disk

At the default 4 fps and 1280px, expect roughly:

| Codec | Rough size per hour |
|---|---|
| h265 | tens of MB |
| h264 | ~2× h265 |
| mjpeg | an order of magnitude more |

Actual size depends heavily on how much the screen changes. A journey that sits
on a static form compresses to almost nothing under h264/h265 and not at all
under MJPEG.

**The server never rotates or prunes.** A long-lived deployment needs a scheduled
cleanup:

```powershell
Get-ChildItem C:\ProgramData\windows-mcp\recordings -File |
  Where-Object LastWriteTime -lt (Get-Date).AddDays(-30) |
  Remove-Item
```

### Access

Recordings show whatever was on screen, which may include data the credentials
system was careful to keep out of the agent's context. Treat `recording_dir` as
sensitive and restrict it:

```powershell
$dir = "C:\ProgramData\windows-mcp\recordings"
icacls $dir /inheritance:r
icacls $dir /grant:r "BUILTIN\Administrators:(OI)(CI)F"
icacls $dir /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)F"
```

### On a kill

The recording is finalized *before* shutdown in the containment ladder,
deliberately — the frames leading up to a security event are the ones worth
having. The on-screen security banner is drawn into them.

---

## Related

- [Policy configuration](policy-config.md) — the `transparency` block
- [Monitoring](monitoring.md) — the audit log that pairs with the video
- [Security architecture](security-architecture.md) — why this is always-on
