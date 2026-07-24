//go:build windows && (amd64 || arm64)

package desktop

import (
	"bytes"
	"image"
	"image/jpeg"
	"log/slog"
)

// frameEncoder consumes fixed-size RGBA frames and writes a video file. Two
// backends implement it: a pure-Go MJPEG-AVI writer (always available, larger
// files) and an ffmpeg-backed H.264/H.265 encoder (far better compression when
// ffmpeg is installed).
type frameEncoder interface {
	writeFrame(img *image.RGBA) error
	close() error
	path() string
}

// createEncoder selects an encoder for a session. It prefers ffmpeg (H.264 /
// H.265) when the requested codec needs it and ffmpeg is available, and falls
// back to the pure-Go MJPEG writer otherwise. base is the output path without
// extension; the encoder appends the right one.
func createEncoder(base string, w, h int, opt RecorderOptions, logger *slog.Logger) (frameEncoder, error) {
	switch opt.Codec {
	case "h264", "h265":
		if ff := resolveFFmpeg(); ff != "" {
			enc, err := newFFmpegEncoder(ff, base+".mp4", w, h, opt)
			if err == nil {
				return enc, nil
			}
			logger.Warn("recorder: ffmpeg encoder failed, falling back to MJPEG", "error", err)
		} else {
			logger.Warn("recorder: ffmpeg not found, falling back to MJPEG (larger files)", "codec", opt.Codec)
		}
	}
	// MJPEG fallback (also the explicit "mjpeg" codec).
	out := base + ".avi"
	avi, err := newAVIWriter(out, w, h, opt.FPS)
	if err != nil {
		return nil, err
	}
	return &mjpegEncoder{avi: avi, quality: opt.Quality, outPath: out}, nil
}

// mjpegEncoder wraps the pure-Go AVI writer, JPEG-encoding each frame.
type mjpegEncoder struct {
	avi     *aviWriter
	quality int
	outPath string
}

func (m *mjpegEncoder) writeFrame(img *image.RGBA) error {
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: m.quality}); err != nil {
		return err
	}
	return m.avi.writeFrame(buf.Bytes())
}

func (m *mjpegEncoder) close() error { return m.avi.close() }
func (m *mjpegEncoder) path() string { return m.outPath }
