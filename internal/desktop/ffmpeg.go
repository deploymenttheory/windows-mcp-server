//go:build windows && (amd64 || arm64)

package desktop

import (
	"fmt"
	"image"
	"io"
	"os/exec"
	"strconv"
	"syscall"
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
}

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
	cmd := exec.Command(ffmpeg, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Env = powerShellEnv() // reconstructed environment

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start ffmpeg: %w", err)
	}
	return &ffmpegEncoder{cmd: cmd, stdin: stdin, outPath: outPath}, nil
}

func (e *ffmpegEncoder) writeFrame(img *image.RGBA) error {
	// image.NewRGBA(0,0,w,h) has Stride == 4*w and Min == (0,0), so Pix is a
	// contiguous row-major RGBA frame of exactly w*h*4 bytes.
	_, err := e.stdin.Write(img.Pix)
	return err
}

func (e *ffmpegEncoder) close() error {
	_ = e.stdin.Close() // signals EOF; ffmpeg finalizes the file
	return e.cmd.Wait()
}

func (e *ffmpegEncoder) path() string { return e.outPath }
