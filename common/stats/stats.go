package stats

import (
	"sync/atomic"
	"time"
)

type SessionStater interface {
	Start() error
	Stop() error
	AddSession(key interface{}, session *Session)
	GetSession(key interface{}) *Session
	RemoveSession(key interface{})
}

type Session struct {
	UploadBytes   int64 `json:"uploadBytes"`
	DownloadBytes int64 `json:"downloadBytes"`

	// Process list including current process and its parents.
	Processes []string `json:"processes"`

	Network      string    `json:"network"`
	LocalAddr    string    `json:"localAddr"`
	RemoteAddr   string    `json:"remoteAddr"`
	SessionStart time.Time `json:"sessionStart"`
	SessionEnd   time.Time `json:"sessionEnd"`
	Extra        string    `json:"extra"`
	OutboundTag  string    `json:"outboundTag"`

	FirstChunkReceived bool      `json:"-"`
	FirstChunkReceive  time.Time `json:"-"`
	FirstChunkDuration string    `json:"firstChunkDuration"`
}

func (s *Session) handleFirstChunk() {
	if !s.FirstChunkReceived {
		s.FirstChunkReceived = true
		s.FirstChunkReceive = time.Now()
	}
}

func (s *Session) AddUploadBytes(n int64) {
	atomic.AddInt64(&s.UploadBytes, n)
}

func (s *Session) AddDownloadBytes(n int64) {
	s.handleFirstChunk()
	atomic.AddInt64(&s.DownloadBytes, n)
}
