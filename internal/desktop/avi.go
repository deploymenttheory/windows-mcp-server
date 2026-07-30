//go:build windows && (amd64 || arm64)

package desktop

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
)

// aviWriter streams Motion-JPEG frames into an AVI 1.0 container. It is a
// self-contained, dependency-free video writer: each frame is a JPEG stored as a
// '00dc' chunk, and the file is a standard RIFF/AVI that players like VLC and
// Windows Media Player open directly. Sizes and frame counts are patched on
// Close via seeks, so frames can be written incrementally during a long session.
//
// Not safe for concurrent use; the recorder owns one aviWriter on one goroutine.
type aviWriter struct {
	f     *os.File
	w, h  int
	fps   int
	count int
	// movieBytes counts bytes written after the 'movi' FOURCC (the frame data).
	movieBytes int
	// index holds one entry per frame for the idx1 table.
	index []aviIndexEntry
}

type aviIndexEntry struct {
	offset uint32 // of the '00dc' chunk, relative to the 'movi' FOURCC
	size   uint32 // JPEG payload size
}

// File offsets of fields patched on Close (constant for this fixed header).
const (
	aviRiffSizePos    = 4
	aviTotalFramesPos = 48
	aviStreamLenPos   = 140
	aviMoviSizePos    = 216
	aviMoviFourccPos  = 220 // position of the 'movi' FOURCC
	aviHeaderSize     = 224 // frame data begins here

	// Sizes used to project whether another frame still fits under the format's
	// uint32 ceiling (see fits).
	aviFrameHeaderSize = 8  // '00dc' FOURCC + payload length
	aviIndexHeaderSize = 8  // 'idx1' FOURCC + chunk length
	aviIndexEntrySize  = 16 // FOURCC + flags + offset + size
)

// u32 and i16 narrow a writer-side int to the width the AVI field uses.
//
// Every value they receive is already bounded by one of the writer's own
// invariants — frame dimensions come from a captured image, fps is normalized
// positive in newAVIWriter, and every size and offset is gated by fits before a
// frame is accepted. A value outside range is therefore a programming error, not
// a runtime condition. They clamp rather than wrap so that if an invariant is
// ever broken the file is merely wrong in one field instead of silently
// mis-addressed, and so the eighteen conversions this replaced do not each need
// their own justification.
func u32(v int) uint32 {
	switch {
	case v < 0:
		return 0
	case v > math.MaxUint32:
		return math.MaxUint32
	default:
		return uint32(v)
	}
}

func i16(v int) int16 {
	switch {
	case v < math.MinInt16:
		return math.MinInt16
	case v > math.MaxInt16:
		return math.MaxInt16
	default:
		return int16(v)
	}
}

func newAVIWriter(path string, w, h, fps int) (*aviWriter, error) {
	if fps <= 0 {
		fps = 4
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	a := &aviWriter{f: f, w: w, h: h, fps: fps}
	if err := a.writeHeader(); err != nil {
		_ = f.Close()
		return nil, err
	}
	return a, nil
}

func (a *aviWriter) writeHeader() error {
	b := make([]byte, 0, aviHeaderSize)
	fourcc := func(s string) { b = append(b, s...) }
	put32 := func(v uint32) { b = binary.LittleEndian.AppendUint32(b, v) }
	put16 := func(v uint16) { b = binary.LittleEndian.AppendUint16(b, v) }
	// rcFrame is signed in the AVI header but the buffer writer is unsigned, so
	// the reinterpretation is the point, not a range error.
	putI16 := func(v int16) {
		b = binary.LittleEndian.AppendUint16(b, uint16(v)) //nolint:gosec // signed field, unsigned writer
	}

	fourcc("RIFF")
	put32(0) // RIFF size (patched)
	fourcc("AVI ")

	fourcc("LIST")
	put32(192)
	fourcc("hdrl")

	// avih (main AVI header, 56 bytes)
	fourcc("avih")
	put32(56)
	put32(u32(1000000 / a.fps)) // dwMicroSecPerFrame
	put32(0)                    // dwMaxBytesPerSec
	put32(0)                    // dwPaddingGranularity
	put32(0x10)                 // dwFlags = AVIF_HASINDEX
	put32(0)                    // dwTotalFrames (patched)
	put32(0)                    // dwInitialFrames
	put32(1)                    // dwStreams
	put32(0)                    // dwSuggestedBufferSize
	put32(u32(a.w))             // dwWidth
	put32(u32(a.h))             // dwHeight
	put32(0)                    // dwReserved[0]
	put32(0)                    // dwReserved[1]
	put32(0)                    // dwReserved[2]
	put32(0)                    // dwReserved[3]

	// strl (stream list)
	fourcc("LIST")
	put32(116)
	fourcc("strl")

	// strh (stream header, 56 bytes)
	fourcc("strh")
	put32(56)
	fourcc("vids")
	fourcc("MJPG")
	put32(0)          // dwFlags
	put16(0)          // wPriority
	put16(0)          // wLanguage
	put32(0)          // dwInitialFrames
	put32(1)          // dwScale
	put32(u32(a.fps)) // dwRate
	put32(0)          // dwStart
	put32(0)          // dwLength (patched)
	put32(0)          // dwSuggestedBufferSize
	put32(0xFFFFFFFF) // dwQuality
	put32(0)          // dwSampleSize
	putI16(0)         // rcFrame.left
	putI16(0)         // rcFrame.top
	putI16(i16(a.w))  // rcFrame.right
	putI16(i16(a.h))  // rcFrame.bottom

	// strf (BITMAPINFOHEADER, 40 bytes)
	fourcc("strf")
	put32(40)
	put32(40)                 // biSize
	put32(u32(a.w))           // biWidth
	put32(u32(a.h))           // biHeight
	put16(1)                  // biPlanes
	put16(24)                 // biBitCount
	fourcc("MJPG")            // biCompression
	put32(u32(a.w * a.h * 3)) // biSizeImage
	put32(0)                  // biXPelsPerMeter
	put32(0)                  // biYPelsPerMeter
	put32(0)                  // biClrUsed
	put32(0)                  // biClrImportant

	// movi list
	fourcc("LIST")
	put32(0) // movi size (patched)
	fourcc("movi")

	if len(b) != aviHeaderSize {
		return fmt.Errorf("avi: internal header size %d, expected %d", len(b), aviHeaderSize)
	}
	_, err := a.f.Write(b)
	return err
}

// ErrAVISizeLimit reports that appending another frame would exceed what AVI 1.0
// can address. Callers should stop recording and finalize; the file written so
// far stays valid.
var ErrAVISizeLimit = errors.New("avi: 4 GiB format limit reached")

// fits reports whether a frame of jpegLen bytes can still be addressed.
//
// Every size in the AVI 1.0 container is a uint32: the RIFF size, the movi size,
// and each idx1 entry's offset. Past 4 GiB those silently wrapped and the file
// was corrupt with no error — which matters here because recording is
// force-enabled by --security and this MJPEG writer is the fallback whenever
// ffmpeg is absent, so it was the forensic artifact of a secured session. The
// format itself is the limit (OpenDML/AVI 2.0 exists precisely to lift it), so
// the fix is to stop cleanly rather than widen a field.
func (a *aviWriter) fits(jpegLen int) bool {
	movie := a.movieBytes + aviFrameHeaderSize + jpegLen
	if jpegLen%2 == 1 {
		movie++ // word-alignment pad
	}
	// idx1 chunk: 8-byte header plus one 16-byte entry per frame, this one included.
	index := aviIndexHeaderSize + aviIndexEntrySize*(a.count+1)
	total := aviHeaderSize + movie + index
	// The RIFF size field stores total-8, so that is the value that must fit.
	return total-8 <= math.MaxUint32
}

// writeFrame appends one JPEG frame.
func (a *aviWriter) writeFrame(jpeg []byte) error {
	if !a.fits(len(jpeg)) {
		return ErrAVISizeLimit
	}
	chunkOffset := u32(aviHeaderSize + a.movieBytes - aviMoviFourccPos)

	var hdr [8]byte
	copy(hdr[0:4], "00dc")
	binary.LittleEndian.PutUint32(hdr[4:8], u32(len(jpeg)))
	if _, err := a.f.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := a.f.Write(jpeg); err != nil {
		return err
	}
	a.movieBytes += 8 + len(jpeg)
	// AVI chunks are word-aligned; pad odd payloads with one byte.
	if len(jpeg)%2 == 1 {
		if _, err := a.f.Write([]byte{0}); err != nil {
			return err
		}
		a.movieBytes++
	}

	a.index = append(a.index, aviIndexEntry{offset: chunkOffset, size: u32(len(jpeg))})
	a.count++
	return nil
}

// close writes the idx1 index, patches the size/frame fields, and closes the
// file. Safe to call once.
func (a *aviWriter) close() error {
	if a.f == nil {
		return nil
	}
	defer func() { _ = a.f.Close(); a.f = nil }()

	// idx1 table.
	idx := make([]byte, 0, 8+16*len(a.index))
	idx = append(idx, "idx1"...)
	idx = binary.LittleEndian.AppendUint32(idx, u32(16*len(a.index)))
	for _, e := range a.index {
		idx = append(idx, "00dc"...)
		idx = binary.LittleEndian.AppendUint32(idx, 0x10) // AVIIF_KEYFRAME
		idx = binary.LittleEndian.AppendUint32(idx, e.offset)
		idx = binary.LittleEndian.AppendUint32(idx, e.size)
	}
	if _, err := a.f.Write(idx); err != nil {
		return err
	}

	total := aviHeaderSize + a.movieBytes + len(idx)
	patch := func(pos int64, v uint32) error {
		var buf [4]byte
		binary.LittleEndian.PutUint32(buf[:], v)
		_, err := a.f.WriteAt(buf[:], pos)
		return err
	}
	if err := patch(aviRiffSizePos, u32(total-8)); err != nil {
		return err
	}
	if err := patch(aviTotalFramesPos, u32(a.count)); err != nil {
		return err
	}
	if err := patch(aviStreamLenPos, u32(a.count)); err != nil {
		return err
	}
	if err := patch(aviMoviSizePos, u32(4+a.movieBytes)); err != nil {
		return err
	}
	return nil
}
