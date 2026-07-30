//go:build windows && (amd64 || arm64)

package desktop

import (
	"context"
	"errors"
	"fmt"
	"image"
	"io"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

// resolveFFmpeg returns the absolute path to ffmpeg, or "" if not found. It
// searches the reconstructed PATH first (so it works even under a stripped
// environment) then the process PATH.
func resolveFFmpeg() string {
	ensureWindowsEnv()
	if p, ok := lookPathIn("ffmpeg", psPathValue); ok {
		return p
	}
	if p, err := exec.LookPath("ffmpeg"); err == nil {
		return p
	}
	return ""
}

// ffmpegEncoder pipes raw RGBA frames to ffmpeg, which encodes H.264 or H.265
// into an MP4. This gives temporal compression — far smaller files than MJPEG
// for screen recordings, where most of the frame is static between frames.
type ffmpegEncoder struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	outPath string
	// cancel kills the child. The encoder owns its own context rather than
	// borrowing a caller's: the process must outlive individual frame writes but
	// must never outlive close.
	cancel context.CancelFunc
}

// ffmpegFinalizeTimeout bounds how long close waits for ffmpeg to finish writing
// the container after stdin is closed.
//
// This matters more than a tidy-up would suggest: close is reached from
// Desktop.Close, which the kill switch's Finalize hook calls. An unbounded
// cmd.Wait meant a wedged ffmpeg could block containment and session shutdown
// indefinitely. Generous enough for a large file to finalize, bounded so it
// cannot hang.
const ffmpegFinalizeTimeout = 30 * time.Second

// ErrFFmpegFinalize reports that ffmpeg had to be killed rather than allowed
// to finish writing the container. The recording on disk is truncated but the
// session shut down; callers surface it as a warning, not a failure.
var ErrFFmpegFinalize = errors.New("ffmpeg did not finalize the recording within the timeout")

func newFFmpegEncoder(ffmpeg, outPath string, w, h int, opt RecorderOptions) (*ffmpegEncoder, error) {
	codec := "libx264"
	if opt.Codec == "h265" {
		codec = "libx265"
	}
	args := []string{
		"-y",
		"-loglevel", "error",
		"-f", "rawvideo",
		"-pixel_format", "rgba",
		"-video_size", fmt.Sprintf("%dx%d", w, h),
		"-framerate", strconv.Itoa(opt.FPS),
		"-i", "-",
		"-an",
		"-c:v", codec,
		"-pix_fmt", "yuv420p",
		"-preset", "veryfast",
		"-crf", "28",
		outPath,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, ffmpeg, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Env = powerShellEnv() // reconstructed environment

	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("ffmpeg stdin pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("start ffmpeg: %w", err)
	}
	return &ffmpegEncoder{cmd: cmd, stdin: stdin, outPath: outPath, cancel: cancel}, nil
}

func (e *ffmpegEncoder) writeFrame(img *image.RGBA) error {
	// image.NewRGBA(0,0,w,h) has Stride == 4*w and Min == (0,0), so Pix is a
	// contiguous row-major RGBA frame of exactly w*h*4 bytes.
	_, err := e.stdin.Write(img.Pix)
	return err
}

func (e *ffmpegEncoder) close() error {
	defer e.cancel()

	_ = e.stdin.Close() // signals EOF; ffmpeg finalizes the file

	done := make(chan error, 1)
	go func() { done <- e.cmd.Wait() }()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("ffmpeg finalize: %w", err)
		}
		return nil
	case <-time.After(ffmpegFinalizeTimeout):
		// Kill it and reap, so shutdown proceeds. The partial file is left for
		// inspection; a truncated recording is better than a hung session.
		e.cancel()
		<-done
		return fmt.Errorf("%w: %s after %s; process killed",
			ErrFFmpegFinalize, e.outPath, ffmpegFinalizeTimeout)
	}
}

func (e *ffmpegEncoder) path() string { return e.outPath }
