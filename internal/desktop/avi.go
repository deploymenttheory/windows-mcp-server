//go:build windows && (amd64 || arm64)

package desktop

import (
	"encoding/binary"
	"fmt"
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
)

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
	u32 := func(v uint32) { b = binary.LittleEndian.AppendUint32(b, v) }
	u16 := func(v uint16) { b = binary.LittleEndian.AppendUint16(b, v) }
	i16 := func(v int16) { b = binary.LittleEndian.AppendUint16(b, uint16(v)) }

	fourcc("RIFF")
	u32(0) // RIFF size (patched)
	fourcc("AVI ")

	fourcc("LIST")
	u32(192)
	fourcc("hdrl")

	// avih (main AVI header, 56 bytes)
	fourcc("avih")
	u32(56)
	u32(uint32(1000000 / a.fps)) // dwMicroSecPerFrame
	u32(0)                       // dwMaxBytesPerSec
	u32(0)                       // dwPaddingGranularity
	u32(0x10)                    // dwFlags = AVIF_HASINDEX
	u32(0)                       // dwTotalFrames (patched)
	u32(0)                       // dwInitialFrames
	u32(1)                       // dwStreams
	u32(0)                       // dwSuggestedBufferSize
	u32(uint32(a.w))             // dwWidth
	u32(uint32(a.h))             // dwHeight
	u32(0)                       // dwReserved[0]
	u32(0)                       // dwReserved[1]
	u32(0)                       // dwReserved[2]
	u32(0)                       // dwReserved[3]

	// strl (stream list)
	fourcc("LIST")
	u32(116)
	fourcc("strl")

	// strh (stream header, 56 bytes)
	fourcc("strh")
	u32(56)
	fourcc("vids")
	fourcc("MJPG")
	u32(0)             // dwFlags
	u16(0)             // wPriority
	u16(0)             // wLanguage
	u32(0)             // dwInitialFrames
	u32(1)             // dwScale
	u32(uint32(a.fps)) // dwRate
	u32(0)             // dwStart
	u32(0)             // dwLength (patched)
	u32(0)             // dwSuggestedBufferSize
	u32(0xFFFFFFFF)    // dwQuality
	u32(0)             // dwSampleSize
	i16(0)             // rcFrame.left
	i16(0)             // rcFrame.top
	i16(int16(a.w))    // rcFrame.right
	i16(int16(a.h))    // rcFrame.bottom

	// strf (BITMAPINFOHEADER, 40 bytes)
	fourcc("strf")
	u32(40)
	u32(40)                    // biSize
	u32(uint32(a.w))           // biWidth
	u32(uint32(a.h))           // biHeight
	u16(1)                     // biPlanes
	u16(24)                    // biBitCount
	fourcc("MJPG")             // biCompression
	u32(uint32(a.w * a.h * 3)) // biSizeImage
	u32(0)                     // biXPelsPerMeter
	u32(0)                     // biYPelsPerMeter
	u32(0)                     // biClrUsed
	u32(0)                     // biClrImportant

	// movi list
	fourcc("LIST")
	u32(0) // movi size (patched)
	fourcc("movi")

	if len(b) != aviHeaderSize {
		return fmt.Errorf("avi: internal header size %d, expected %d", len(b), aviHeaderSize)
	}
	_, err := a.f.Write(b)
	return err
}

// writeFrame appends one JPEG frame.
func (a *aviWriter) writeFrame(jpeg []byte) error {
	chunkOffset := uint32(aviHeaderSize + a.movieBytes - aviMoviFourccPos)

	var hdr [8]byte
	copy(hdr[0:4], "00dc")
	binary.LittleEndian.PutUint32(hdr[4:8], uint32(len(jpeg)))
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

	a.index = append(a.index, aviIndexEntry{offset: chunkOffset, size: uint32(len(jpeg))})
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
	idx = binary.LittleEndian.AppendUint32(idx, uint32(16*len(a.index)))
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
	if err := patch(aviRiffSizePos, uint32(total-8)); err != nil {
		return err
	}
	if err := patch(aviTotalFramesPos, uint32(a.count)); err != nil {
		return err
	}
	if err := patch(aviStreamLenPos, uint32(a.count)); err != nil {
		return err
	}
	if err := patch(aviMoviSizePos, uint32(4+a.movieBytes)); err != nil {
		return err
	}
	return nil
}
