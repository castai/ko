package conntest

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"time"
)

const (
	minBackoff     = time.Second
	maxBackoff     = 30 * time.Second
	keepAliveEvery = 30 * time.Second
)

func (m *Mesh) runProber(ctx context.Context, target Pod) {
	addr := net.JoinHostPort(target.IP, fmt.Sprintf("%d", m.cfg.ListenPort))
	dialer := &net.Dialer{
		Timeout:   m.cfg.Timeout.std(),
		KeepAlive: keepAliveEvery,
	}
	backoff := minBackoff
	m.metrics.setState(target, stateConnecting)
	for {
		if ctx.Err() != nil {
			return
		}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			m.metrics.setState(target, stateFailed)
			m.metrics.addError(target)
			m.log.Warnf("conntest: dial %s: %v", addr, err)
			if !sleepCtx(ctx, backoff) {
				return
			}
			backoff = min(backoff*2, maxBackoff)
			m.metrics.setState(target, stateConnecting)
			continue
		}
		backoff = minBackoff
		err = m.pingLoop(ctx, conn, target)
		conn.Close()
		if err == nil || ctx.Err() != nil {
			return
		}
		m.metrics.setState(target, stateFailed)
		m.metrics.addError(target)
		m.log.Warnf("conntest: %s: %v", addr, err)
		if !sleepCtx(ctx, backoff) {
			return
		}
		backoff = min(backoff*2, maxBackoff)
		m.metrics.setState(target, stateConnecting)
	}
}

func (m *Mesh) pingLoop(ctx context.Context, conn net.Conn, target Pod) error {
	m.metrics.setState(target, stateConnected)
	reader := bufio.NewReader(conn)
	ticker := time.NewTicker(m.cfg.Interval.std())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		if err := conn.SetWriteDeadline(time.Now().Add(m.cfg.Timeout.std())); err != nil {
			return err
		}
		start := time.Now()
		if _, err := conn.Write([]byte(pingMsg)); err != nil {
			return err
		}
		if err := conn.SetReadDeadline(time.Now().Add(m.cfg.Timeout.std())); err != nil {
			return err
		}
		reply, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		if reply != pongMsg {
			return fmt.Errorf("unexpected reply %q", reply)
		}
		m.metrics.setRTT(target, time.Since(start).Seconds())
		m.metrics.addPing(target)
	}
}
