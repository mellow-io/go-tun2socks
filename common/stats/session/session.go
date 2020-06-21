package session

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/text/language"
	"golang.org/x/text/message"

	"github.com/eycorsican/go-tun2socks/common/log"
	"github.com/eycorsican/go-tun2socks/common/stats"
)

const maxCompletedSessions = 500

type simpleSessionStater struct {
	sync.Mutex
	sessions          sync.Map
	completedSessions []stats.Session
	server            *http.Server
}

func NewSimpleSessionStater() stats.SessionStater {
	return &simpleSessionStater{}
}

func chain(processes []string) string {
	var l []string
	for i := len(processes) - 1; i >= 0; i-- {
		if i == 0 {
			l = append(l, fmt.Sprintf("<span class=\"highlight\">%v</span>", processes[i]))
		} else {
			l = append(l, processes[i])
		}
	}
	return strings.Join(l, " ↣ ")
}

func (s *simpleSessionStater) sessionStatsJsonHandler(respw http.ResponseWriter, req *http.Request) {
	// Make a snapshot.
	var sessions []stats.Session
	s.sessions.Range(func(key, value interface{}) bool {
		sess := value.(*stats.Session)
		sessions = append(sessions, *sess)
		return true
	})

	// Sort by session start time.
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].SessionStart.Sub(sessions[j].SessionStart) < 0
	})

	for idx, _ := range sessions {
		sess := &sessions[idx]
		duration := sess.FirstChunkReceive.Sub(sess.SessionStart)
		if duration > 0 {
			sess.FirstChunkDuration = duration.Round(time.Millisecond).String()
		}
	}
	for idx, _ := range s.completedSessions {
		sess := &s.completedSessions[idx]
		duration := sess.FirstChunkReceive.Sub(sess.SessionStart)
		if duration > 0 {
			sess.FirstChunkDuration = duration.Round(time.Millisecond).String()
		}
	}

	statSessions := &StatSessions{
		ActiveSessions:    sessions,
		CompletedSessions: s.completedSessions,
	}

	respw.Header().Set("Access-Control-Allow-Headers", "*")
	respw.Header().Set("Access-Control-Allow-Origin", "*")
	respw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(respw).Encode(statSessions)
}

type StatSessions struct {
	ActiveSessions    []stats.Session `json:"activeSessions"`
	CompletedSessions []stats.Session `json:"completedSessions"`
}

func (s *simpleSessionStater) sessionStatsHandler(respw http.ResponseWriter, req *http.Request) {
	// Make a snapshot.
	var sessions []stats.Session
	s.sessions.Range(func(key, value interface{}) bool {
		sess := value.(*stats.Session)
		sessions = append(sessions, *sess)
		return true
	})

	// Sort by session start time.
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].SessionStart.Sub(sessions[j].SessionStart) < 0
	})

	p := message.NewPrinter(language.English)
	tablePrint := func(w io.Writer, sessions []stats.Session) {
		fmt.Fprintf(w, "<table style=\"border=4px solid\">")
		fmt.Fprintf(w, "<tr><td>Process</td><td>Network</td><td>Duration</td><td>Local Addr</td><td>Remote Addr</td><td>Upload Bytes</td><td>Download Bytes</td><td>Response Time</td><td>Extra</td><td>Outbound</td></tr>")
		for _, sess := range sessions {
			var duration time.Duration
			if sess.SessionEnd.IsZero() {
				duration = time.Now().Sub(sess.SessionStart).Round(time.Second)
			} else {
				duration = sess.SessionEnd.Sub(sess.SessionStart).Round(time.Second)
			}
			responseTime := sess.FirstChunkReceive.Sub(sess.SessionStart).Round(time.Millisecond)
			if responseTime < 0 {
				responseTime = 0
			}
			fmt.Fprintf(w, "<tr><td>%v</td><td>%v</td><td>%v</td><td>%v</td><td>%v</td><td>%v</td><td>%v</td><td>%v</td><td>%v</td><td>%v</td></tr>",
				chain(sess.Processes),
				sess.Network,
				duration,
				sess.LocalAddr,
				sess.RemoteAddr,
				p.Sprintf("%d", atomic.LoadInt64(&sess.UploadBytes)),
				p.Sprintf("%d", atomic.LoadInt64(&sess.DownloadBytes)),
				responseTime.String(),
				sess.Extra,
				sess.OutboundTag,
			)
		}
		fmt.Fprintf(w, "</table>")
	}

	w := bufio.NewWriter(respw)
	fmt.Fprintf(w, "<html>")
	fmt.Fprintf(w, `<head><style>
table, th, td {
  border: 1px solid black;
  border-collapse: collapse;
  text-align: right;
  padding: 4;
  font-size: small;
}

.highlight {
  font-weight: bold;
}
</style></head>`)
	fmt.Fprintf(w, "<p>Active sessions %d</p>", len(sessions))
	tablePrint(w, sessions)
	fmt.Fprintf(w, "<br/><br/>")
	fmt.Fprintf(w, "<p>Recently completed sessions %d</p>", len(s.completedSessions))
	s.Lock()
	tablePrint(w, s.completedSessions)
	s.Unlock()
	fmt.Fprintf(w, "</html>")
	w.Flush()
}

func (s *simpleSessionStater) Start() error {
	log.Infof("Start session stater.")
	mux := http.NewServeMux()
	mux.HandleFunc("/stats/session/plain", s.sessionStatsHandler)
	mux.HandleFunc("/stats/session/json", s.sessionStatsJsonHandler)
	s.server = &http.Server{Addr: "127.0.0.1:6001", Handler: mux}
	go s.server.ListenAndServe()
	return nil
}

func (s *simpleSessionStater) Stop() error {
	log.Infof("Stop session stater.")
	return s.server.Close()
}

func (s *simpleSessionStater) AddSession(key interface{}, session *stats.Session) {
	s.sessions.Store(key, session)
}

func (s *simpleSessionStater) GetSession(key interface{}) *stats.Session {
	if sess, ok := s.sessions.Load(key); ok {
		return sess.(*stats.Session)
	}
	return nil
}

func (s *simpleSessionStater) RemoveSession(key interface{}) {
	s.Lock()
	defer s.Unlock()

	if sess, ok := s.sessions.Load(key); ok {
		sess2 := *(sess.(*stats.Session))
		sess2.SessionEnd = time.Now()
		s.completedSessions = append(s.completedSessions, sess2)
		if len(s.completedSessions) > maxCompletedSessions {
			s.completedSessions = s.completedSessions[1:]
		}
	}
	s.sessions.Delete(key)
}
