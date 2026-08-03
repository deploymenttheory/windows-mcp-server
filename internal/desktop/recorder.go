//go:build windows && (amd64 || arm64)

package desktop

import (
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// RecorderOptions configures session video recording.
type RecorderOptions struct {
	// Dir is the output directory for session recordings. Empty disables it.
	Dir string
	// FPS is the capture rate (default 4).
	FPS int
	// MaxWidth downscales frames wider than this (default 1280; 0 = full res).
	MaxWidth int
	// Quality is the MJPEG JPEG quality 1-100 (default 60).
	Quality int
	// Codec selects the video encoder: "h264" or "h265" use ffmpeg when
	// available (small files) and fall back to pure-Go MJPEG-AVI when not;
	// "mjpeg" forces the pure-Go writer. Default "h264".
	Codec string
	// Stamp is the shared session stamp used to name the output. Empty means the
	// recorder mints its own from the clock. When set, the recording file
	// (session-<stamp>.*) correlates by name with the audit file the same stamp
	// named, which is what lets an evidence bundle pair them.
	Stamp string
}

func (o RecorderOptions) withDefaults() RecorderOptions {
	if o.FPS <= 0 {
		o.FPS = 4
	}
	if o.MaxWidth == 0 {
		o.MaxWidth = 1280
	}
	if o.Quality <= 0 {
		o.Quality = 60
	}
	if o.Codec == "" {
		o.Codec = "h264"
	}
	return o
}

// RecordingStatus reports the recorder's state.
type RecordingStatus struct {
	Recording   bool
	VideoPath   string
	MarkersPath string
	Frames      int
	DurationSec float64
	FPS         int
}

// recorder captures the screen at a fixed rate and writes an MJPEG AVI plus a
// JSONL marker log, so an entire session is tracked as a single video file. It
// runs on its own goroutine and captures via the standalone GDI pipeline
// (captureScreen), independent of the engine STA thread.
type recorder struct {
	opt    RecorderOptions
	logger *slog.Logger

	base        string
	videoPath   string
	markersPath string

	stop chan struct{}
	done chan struct{}

	mu      sync.Mutex
	started time.Time
	frames  int
	markers *os.File
}

func startRecorder(opt RecorderOptions, logger *slog.Logger) (*recorder, error) {
	opt = opt.withDefaults()
	if err := os.MkdirAll(opt.Dir, 0o755); err != nil {
		return nil, fmt.Errorf("recorder: create dir: %w", err)
	}
	stamp := opt.Stamp
	if stamp == "" {
		stamp = time.Now().Format("20060102-150405")
	}
	base := filepath.Join(opt.Dir, "session-"+stamp)

	markers, err := os.Create(base + ".jsonl")
	if err != nil {
		return nil, fmt.Errorf("recorder: create markers log: %w", err)
	}

	// Predict the output extension for status reporting before the first frame.
	ext := ".avi"
	if (opt.Codec == "h264" || opt.Codec == "h265") && resolveFFmpeg() != "" {
		ext = ".mp4"
	}

	r := &recorder{
		opt:         opt,
		logger:      logger,
		base:        base,
		videoPath:   base + ext,
		markersPath: base + ".jsonl",
		stop:        make(chan struct{}),
		done:        make(chan struct{}),
		started:     time.Now(),
		markers:     markers,
	}
	r.writeMarker("recording started")
	go r.run()
	return r, nil
}

func (r *recorder) run() {
	defer close(r.done)

	var enc frameEncoder
	var baseW, baseH int
	defer func() {
		if enc != nil {
			if err := enc.close(); err != nil {
				r.logger.Warn("recorder: finalize video failed", "error", err)
			}
		}
	}()

	interval := time.Second / time.Duration(r.opt.FPS)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stop:
			return
		case <-ticker.C:
		}

		img, _, _, _, err := captureScreen(r.opt.MaxWidth)
		if err != nil {
			r.logger.Warn("recorder: capture failed", "error", err)
			continue
		}

		if enc == nil {
			baseW, baseH = img.Rect.Dx(), img.Rect.Dy()
			e, err := createEncoder(r.base, baseW, baseH, r.opt, r.logger)
			if err != nil {
				r.logger.Warn("recorder: create encoder failed", "error", err)
				return
			}
			enc = e
			r.mu.Lock()
			r.videoPath = e.path()
			r.mu.Unlock()
		} else if img.Rect.Dx() != baseW || img.Rect.Dy() != baseH {
			// Resolution changed mid-session (monitor added/removed): rescale to
			// the original frame size so the encoder's fixed size stays valid.
			img = resizeRGBA(img, baseW, baseH)
		}

		if err := enc.writeFrame(img); err != nil {
			// Reaching the container's addressable limit is an expected end state,
			// not a failure: the file written so far is valid and the deferred
			// close() finalizes it. Report it distinctly so a truncated recording is
			// never mistaken for a complete one, and mark the timeline.
			if errors.Is(err, ErrAVISizeLimit) {
				r.mu.Lock()
				frames, path := r.frames, r.videoPath
				r.mu.Unlock()
				r.logger.Error("recorder: stopped at the AVI 4 GiB format limit; the recording is "+
					"valid up to this point but does NOT cover the rest of the session",
					"frames", frames, "path", path)
				r.writeMarker("recording stopped: AVI 4 GiB format limit reached")
				return
			}
			r.logger.Warn("recorder: write frame failed", "error", err)
			return
		}
		r.mu.Lock()
		r.frames++
		r.mu.Unlock()
	}
}

// Mark records a timestamped label into the session marker log, so the video
// timeline can be aligned with actions/journey steps.
func (r *recorder) mark(label string) {
	r.writeMarker(label)
}

func (r *recorder) writeMarker(label string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.markers == nil {
		return
	}
	entry := map[string]any{
		"t_ms":  time.Since(r.started).Milliseconds(),
		"frame": r.frames,
		"label": label,
	}
	b, _ := json.Marshal(entry)
	_, _ = r.markers.Write(append(b, '\n'))
}

func (r *recorder) status() RecordingStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	return RecordingStatus{
		Recording:   true,
		VideoPath:   r.videoPath,
		MarkersPath: r.markersPath,
		Frames:      r.frames,
		DurationSec: time.Since(r.started).Seconds(),
		FPS:         r.opt.FPS,
	}
}

func (r *recorder) close() {
	select {
	case <-r.stop:
	default:
		r.writeMarker("recording stopped")
		close(r.stop)
	}
	<-r.done
	r.mu.Lock()
	if r.markers != nil {
		_ = r.markers.Close()
		r.markers = nil
	}
	r.mu.Unlock()
}

// resizeRGBA nearest-neighbor resizes an RGBA image to w×h.
func resizeRGBA(src *image.RGBA, w, h int) *image.RGBA {
	dst := image.NewRGBA(image.Rect(0, 0, w, h))
	sw, sh := src.Rect.Dx(), src.Rect.Dy()
	if sw == 0 || sh == 0 {
		return dst
	}
	for y := range h {
		sy := y * sh / h
		for x := range w {
			sx := x * sw / w
			so := src.PixOffset(sx, sy)
			do := dst.PixOffset(x, y)
			copy(dst.Pix[do:do+4], src.Pix[so:so+4])
		}
	}
	return dst
}
