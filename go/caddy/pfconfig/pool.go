package caddypfconfig

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/inverse-inc/packetfence/go/caddy/caddy"
	"github.com/inverse-inc/packetfence/go/caddy/caddy/caddyhttp/httpserver"
	"github.com/inverse-inc/packetfence/go/pfconfigdriver"
)

func init() {
	caddy.RegisterPlugin("pfconfigpool", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

// Setup an async goroutine that refreshes the pfconfig pool every second
func setup(c *caddy.Controller) error {
	noRlockPaths := []string{}
	for c.Next() {
		for c.NextBlock() {
			switch c.Val() {
			case "dont_rlock":
				args := c.RemainingArgs()

				if len(args) != 1 {
					return c.ArgErr()
				} else {
					path := args[0]
					noRlockPaths = append(noRlockPaths, path)
					fmt.Println("Ignoring the following path for pfconfigpool rlock" + path)
				}
			default:
				return c.ArgErr()
			}
		}
	}

	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return PoolHandler{Next: next, refreshLauncher: &sync.Once{}, noRlockPaths: noRlockPaths}
	})

	return nil
}

type PoolHandler struct {
	Next            httpserver.Handler
	refreshLauncher *sync.Once
	noRlockPaths    []string
}

// Middleware that ensures there is a read-lock on the pool during every request and released when the request is done
func (h PoolHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	for _, noRlock := range h.noRlockPaths {
		if strings.HasSuffix(r.URL.Path, noRlock) {
			return h.Next.ServeHTTP(w, r)
		}
	}

	id, err := pfconfigdriver.PfconfigPool.ReadLock(r.Context())
	if err == nil {
		defer pfconfigdriver.PfconfigPool.ReadUnlock(r.Context(), id)

		// We launch the refresh job once, the first time a request comes in
		// This ensures that the pool will run with a context that represents a request (log level for instance)
		h.refreshLauncher.Do(func() {
			ctx := r.Context()
			go func(ctx context.Context) {
				for {
					pfconfigdriver.PfconfigPool.Refresh(ctx)
					time.Sleep(1 * time.Second)
				}
			}(ctx)
		})

		return h.Next.ServeHTTP(w, r)
	} else {
		panic("Unable to obtain pfconfigpool lock in caddy middleware")
	}
}
