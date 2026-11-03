package probe

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Client runs probes against a node's endpoint, as rayctl probe -channel
// does and the Niko client can.
type Client struct {
	HTTP      *http.Client // the subscription's: TLS pinned, X25519MLKEM768
	Base      string       // https://host:port
	Authorize func(*http.Request)
}

// Transfer is one TCP probe: what the client saw and the server's result.
type Transfer struct {
	Bytes    int64
	Duration time.Duration
	Server   Result
}

// Mbps is the client's rate.
func (t Transfer) Mbps() float64 {
	if t.Duration <= 0 {
		return 0
	}
	return float64(t.Bytes) * 8 / t.Duration.Seconds() / 1e6
}

func (c Client) do(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, body)
	if err != nil {
		return nil, err
	}
	c.Authorize(req)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		_ = resp.Body.Close()
		return nil, fmt.Errorf("%s %s: HTTP %d %s", method, path, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return resp, nil
}

// Down receives n bytes.
func (c Client) Down(ctx context.Context, n int64) (Transfer, error) {
	start := time.Now()
	resp, err := c.do(ctx, http.MethodGet, PathDown+"?bytes="+strconv.FormatInt(n, 10), nil)
	if err != nil {
		return Transfer{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	got, err := io.Copy(io.Discard, resp.Body)
	t := Transfer{Bytes: got, Duration: time.Since(start)}
	if err != nil {
		return t, err
	}
	t.Server = parseResult(resp.Trailer.Get(ResultTrailer))
	return t, nil
}

// Up sends n bytes.
func (c Client) Up(ctx context.Context, n int64) (Transfer, error) {
	start := time.Now()
	resp, err := c.do(ctx, http.MethodPost, PathUp+"?bytes="+strconv.FormatInt(n, 10), io.LimitReader(zeros{}, n))
	if err != nil {
		return Transfer{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	t := Transfer{Bytes: n, Duration: time.Since(start)}
	err = json.NewDecoder(resp.Body).Decode(&t.Server)
	return t, err
}

type zeros struct{}

func (zeros) Read(b []byte) (int, error) {
	clear(b)
	return len(b), nil
}

func parseResult(s string) Result {
	var r Result
	var t TCPInfo
	for _, kv := range strings.Split(s, ";") {
		k, v, _ := strings.Cut(strings.TrimSpace(kv), "=")
		n, _ := strconv.ParseUint(v, 10, 64)
		switch k {
		case "bytes":
			r.Bytes = int64(n)
		case "ms":
			r.Ms = int64(n)
		case "rtt_us":
			t.RTTus, r.TCP = uint32(n), &t
		case "rttvar_us":
			t.RTTVarus = uint32(n)
		case "min_rtt_us":
			t.MinRTTus = uint32(n)
		case "retrans":
			t.Retrans = uint32(n)
		case "delivery_bps":
			t.DeliveryBps = n
		case "cwnd":
			t.Cwnd = uint32(n)
		case "pmtu":
			t.PMTU = uint32(n)
		}
	}
	return r
}

// Echo is one UDP echo: the client's count and the server's, from which
// the loss each way follows.
type Echo struct {
	Sent, Received int
	Server         UDPSummary
	RTTMin         time.Duration
	RTTAvg         time.Duration
	RTTMax         time.Duration
	Jitter         time.Duration // mean difference of consecutive RTTs
	Reordered      int           // echoes that came after a later one
}

// LostUp is what did not reach the server; LostDown what it echoed that
// did not come back.
func (e Echo) LostUp() int   { return e.Sent - int(e.Server.Received) }
func (e Echo) LostDown() int { return int(e.Server.Echoed) - e.Received }

// Echo sends count datagrams of size bytes, one per interval, to the echo
// on the endpoint's port number, then asks the server for its count.
func (c Client) Echo(ctx context.Context, count, size int, interval time.Duration) (Echo, error) {
	if size < HeaderSize {
		return Echo{}, fmt.Errorf("a datagram has at least %d bytes", HeaderSize)
	}
	resp, err := c.do(ctx, http.MethodPost, PathUDP, nil)
	if err != nil {
		return Echo{}, err
	}
	var sess UDPSession
	err = json.NewDecoder(resp.Body).Decode(&sess)
	_ = resp.Body.Close()
	token, derr := base64.RawURLEncoding.DecodeString(sess.Token)
	if err != nil || derr != nil || len(token) != tokenSize || sess.Port == 0 {
		return Echo{}, errors.New("the node has no UDP echo")
	}
	host := strings.TrimPrefix(c.Base, "https://")
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	conn, err := net.Dial("udp", net.JoinHostPort(host, strconv.Itoa(sess.Port)))
	if err != nil {
		return Echo{}, err
	}
	defer func() { _ = conn.Close() }()

	var (
		mu   sync.Mutex
		rtts = map[uint32]time.Duration{}
		seen []uint32
	)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			if n < HeaderSize || !bytes.Equal(buf[:tokenSize], token) {
				continue
			}
			seq := binary.BigEndian.Uint32(buf[tokenSize:])
			sent := time.Unix(0, int64(binary.BigEndian.Uint64(buf[tokenSize+4:])))
			mu.Lock()
			if _, dup := rtts[seq]; !dup {
				rtts[seq] = time.Since(sent)
				seen = append(seen, seq)
			}
			mu.Unlock()
		}
	}()
	d := make([]byte, size)
	copy(d, token)
	_, _ = rand.Read(d[HeaderSize:])
	e := Echo{}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for i := 0; i < count; i++ {
		binary.BigEndian.PutUint32(d[tokenSize:], uint32(i))
		binary.BigEndian.PutUint64(d[tokenSize+4:], uint64(time.Now().UnixNano()))
		if _, err := conn.Write(d); err == nil {
			e.Sent++
		}
		select {
		case <-ctx.Done():
			return e, ctx.Err()
		case <-tick.C:
		}
	}
	// Late echoes: wait a second, then stop reading.
	time.Sleep(time.Second)
	_ = conn.SetReadDeadline(time.Now())
	<-done

	resp, err = c.do(ctx, http.MethodGet, PathUDP+"?token="+sess.Token, nil)
	if err != nil {
		return e, err
	}
	err = json.NewDecoder(resp.Body).Decode(&e.Server)
	_ = resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()
	e.Received = len(seen)
	var sum, jit time.Duration
	var maxSeq uint32
	for i, seq := range seen {
		r := rtts[seq]
		if i == 0 || r < e.RTTMin {
			e.RTTMin = r
		}
		e.RTTMax = max(e.RTTMax, r)
		sum += r
		if i > 0 {
			jit += (r - rtts[seen[i-1]]).Abs()
			if seq < maxSeq {
				e.Reordered++
			}
		}
		maxSeq = max(maxSeq, seq)
	}
	if n := len(seen); n > 0 {
		e.RTTAvg = sum / time.Duration(n)
		if n > 1 {
			e.Jitter = jit / time.Duration(n-1)
		}
	}
	return e, err
}
