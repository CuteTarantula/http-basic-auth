package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	_ "net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.uber.org/atomic"

	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/tg123/go-htpasswd"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sync/errgroup"
)

func main() {
	logger, _ := zap.Config{
		Encoding:    "json",
		Level:       zap.NewAtomicLevelAt(zapcore.DebugLevel),
		OutputPaths: []string{"stdout"},
		EncoderConfig: zapcore.EncoderConfig{
			MessageKey:   "message",
			LevelKey:     "level",
			EncodeLevel:  zapcore.CapitalLevelEncoder,
			TimeKey:      "time",
			EncodeTime:   zapcore.ISO8601TimeEncoder,
			CallerKey:    "caller",
			EncodeCaller: zapcore.ShortCallerEncoder,
		},
	}.Build()

	log := zapr.NewLogger(logger)
	defer logger.Sync() // nolint: errcheck

	app := &cli.App{
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "addr",
				EnvVars: []string{"ADDR"},
				Value:   ":3311",
			},
			&cli.StringFlag{
				Name:    "metrics-addr",
				EnvVars: []string{"METRICS_ADDR"},
				Value:   ":3000",
			},
			&cli.BoolFlag{
				Name:    "enable-pprof",
				EnvVars: []string{"ENABLE_PPROF"},
				Value:   false,
			},
			&cli.StringFlag{
				Name:    "pprof-addr",
				EnvVars: []string{"PPROF_ADDR"},
				Value:   ":6060",
			},
			&cli.StringFlag{
				Name:     "target-uri",
				EnvVars:  []string{"TARGET_URI"},
				Required: true,
			},
			&cli.StringFlag{
				Name:     "auth",
				Usage:    "basic auth credentials, format: username:(bcrypt hash of password)",
				EnvVars:  []string{"AUTH"},
				Required: true,
			},
			&cli.DurationFlag{
				Name:    "auth-timeout",
				EnvVars: []string{"AUTH_TIMEOUT"},
				Value:   24 * time.Hour,
			},
			&cli.Uint64Flag{
				Name:    "rate-limit-max",
				EnvVars: []string{"RATE_LIMIT_MAX"},
				Value:   5,
			},
			&cli.DurationFlag{
				Name:    "rate-limit-duration",
				EnvVars: []string{"RATE_LIMIT_DURATION"},
				Value:   time.Minute,
			},
		},
		Action: func(c *cli.Context) error {
			eg, ctx := errgroup.WithContext(c.Context)

			u, err := url.Parse(c.String("target-uri"))
			if err != nil {
				log.Error(err, "parse target")
				return err
			}

			auth := c.String("auth")
			user := auth[:strings.IndexByte(auth, ':')]
			pass := auth[strings.IndexByte(auth, ':')+1:]

			md5Pass, err := htpasswd.AcceptMd5(pass)
			if err != nil {
				log.Error(err, "md5 password")
			}
			if md5Pass == nil {
				log.Info("md5 password is nil")
			}

			if c.Bool("enable-pprof") {
				eg.Go(func() error {
					return runHTTP(ctx, log, c.String("pprof-addr"), "pprof", http.DefaultServeMux)
				})
			}

			eg.Go(func() error {
				r := mux.NewRouter()
				r.Path("/metrics").Handler(promhttp.Handler())
				return runHTTP(ctx, log, c.String("metrics-addr"), "metrics", r)
			})

			var unhashed atomic.String

			eg.Go(func() error {
				proxy := &httputil.ReverseProxy{
					Rewrite: func(r *httputil.ProxyRequest) {
						r.SetURL(u)
						r.Out.Host = u.Host
						ui := u.User
						if ui != nil {
							r.Out.Header.Set("authorization", fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(ui.String()))))
						}
					},
				}

				limiter := newRateLimiter(ctx, c.Uint64("rate-limit-max"), c.Duration("rate-limit-duration"))

				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					ip := userIP(r)
					username, password, ok := r.BasicAuth()
					if !ok {
						if err := limiter.Wait(r.Context(), ip); err != nil {
							log.Error(errors.New("rate limit exceeded"), "no auth provided", "ip", ip)
							http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
							return
						}
						w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
						http.Error(w, "Unauthorized", http.StatusUnauthorized)
						return
					}

					unh := unhashed.Load()
					if unh != "" && unh == password && username == user {
						proxy.ServeHTTP(w, r)
						return
					}

					if err := limiter.Wait(r.Context(), ip); err != nil {
						log.Error(errors.New("rate limit exceeded"), "incorrect auth", "ip", ip)
						http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
						return
					}

					err := bcrypt.CompareHashAndPassword([]byte(pass), []byte(password))
					if err == nil && username == user {
						unhashed.Store(password)
						proxy.ServeHTTP(w, r)
						return
					}
					if err != nil {
						log.Error(err, "bycrypt incorrect auth", "ip", ip)
					}

					if md5Pass != nil && md5Pass.MatchesPassword(password) && username == user {
						unhashed.Store(password)
						proxy.ServeHTTP(w, r)
						return
					}

					w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
				})

				return runHTTP(ctx, log, c.String("addr"), "server", handler)
			})

			eg.Go(func() error {
				t := time.NewTicker(c.Duration("auth-timeout"))
				defer t.Stop()
				for {
					select {
					case <-t.C:
						unhashed.Store("")
					case <-ctx.Done():
						return ctx.Err()
					}
				}
			})

			eg.Go(func() error {
				sigs := make(chan os.Signal, 1)
				signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

				select {
				case sig := <-sigs:
					log.Info("terminating signal received", "sig", sig)
					return fmt.Errorf("signal %s received", sig.String())
				case <-ctx.Done():
					return ctx.Err()
				}
			})

			return eg.Wait()
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Error(err, "run")
		os.Exit(1)
	}
}

func runHTTP(ctx context.Context, log logr.Logger, addr, name string, handler http.Handler) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("could not listen for %s on address %w", name, err)

	}

	s := &http.Server{
		Handler: handler,
	}

	go func() {
		<-ctx.Done()
		shutdownContext, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		log.Info(fmt.Sprintf("initiated a graceful shutdown of the %s server", name))
		err := s.Shutdown(shutdownContext)
		if errors.Is(err, context.DeadlineExceeded) {
			log.Info(fmt.Sprintf("%s server terminated abruptly, necessitating a forced closure.", name))
			s.Close() // nolint: errcheck
		}
	}()

	log.Info(fmt.Sprintf("%s server is up and running", name), "addr", l.Addr().String())
	return s.Serve(l)
}

type rateLimiterTimestamp struct {
	count     uint64
	timestamp time.Time
}

type rateLimiter struct {
	keys map[string]*rateLimiterTimestamp
	max  uint64
	dur  time.Duration
	mux  *sync.Mutex
}

func newRateLimiter(ctx context.Context, max uint64, d time.Duration) *rateLimiter {
	r := rateLimiter{
		keys: make(map[string]*rateLimiterTimestamp),
		max:  max,
		mux:  &sync.Mutex{},
		dur:  d,
	}
	go func() {
		ticker := time.NewTicker(d / 2)
		for ctx.Err() == nil {
			<-ticker.C
			r.clearOldKeys()
		}
	}()

	return &r
}

func (i *rateLimiter) clearOldKeys() {
	i.mux.Lock()
	defer i.mux.Unlock()
	for k, v := range i.keys {
		if time.Since(v.timestamp) > i.dur {
			delete(i.keys, k)
		}
	}
}

func (i *rateLimiter) Wait(ctx context.Context, key string) error {
	i.mux.Lock()
	defer i.mux.Unlock()
	l, exists := i.keys[key]

	if !exists {
		i.keys[key] = &rateLimiterTimestamp{
			count:     1,
			timestamp: time.Now(),
		}
		return nil
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	for l.count >= i.max {
		return fmt.Errorf("rate limit exceeded for %s", key)
	}

	l.count++
	return nil
}

func userIP(r *http.Request) string {
	a := r.Header.Get("X-Forwarded-For")
	if a == "" {
		a = r.RemoteAddr
	}
	return strings.Split(a, ",")[0]
}
