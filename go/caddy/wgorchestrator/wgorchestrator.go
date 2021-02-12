package wgorchestrator

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/inverse-inc/packetfence/go/caddy/caddy"
	"github.com/inverse-inc/packetfence/go/caddy/caddy/caddyhttp/httpserver"
	"github.com/inverse-inc/packetfence/go/db"
	"github.com/inverse-inc/packetfence/go/log"
	"github.com/inverse-inc/packetfence/go/panichandler"
	"github.com/inverse-inc/packetfence/go/pfconfigdriver"
	"github.com/inverse-inc/packetfence/go/remoteclients"
	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/jcuga/golongpoll"
	"github.com/jinzhu/gorm"
)

var handledPath = regexp.MustCompile(`^/api/v1/remote_client`)

const defaultPollTimeout = 30 * time.Second
const maxSessionIdleTime = 5 * time.Minute
const LONG_POLL_CONTEXT_KEY = "GLP-GIN-MIDDLEWARE"
const DB_CLIENT_CONTEXT_KEY = "DB-CLIENT-GIN-MIDDLEWARE"

// Register the plugin in caddy
func init() {
	caddy.RegisterPlugin("wgorchestrator", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

type WgorchestratorHandler struct {
	Next       httpserver.Handler
	router     *gin.Engine
	privateKey [32]byte
	publicKey  [32]byte
}

// Setup the log-tailer middleware
// Also loads the pfconfig resources and registers them in the pool
func setup(c *caddy.Controller) error {
	ctx := log.LoggerNewContext(context.Background())

	wgOrchestrator, err := buildWgorchestratorHandler(ctx)

	if err != nil {
		return err
	}

	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		wgOrchestrator.Next = next
		return wgOrchestrator
	})

	return nil
}

func buildWgorchestratorHandler(ctx context.Context) (WgorchestratorHandler, error) {

	wgOrchestrator := WgorchestratorHandler{}

	remoteclients.InitGlobal()
	pfconfigdriver.PfconfigPool.AddRefreshable(ctx, remoteclients.GlobalRemoteConnectionProfiles)
	pfconfigdriver.PfconfigPool.AddStruct(ctx, &pfconfigdriver.Config.RolesChildren)

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	if sharedutils.IsEnabled(sharedutils.EnvOrDefault("WGORCHESTRATOR_GIN_ACCESS_LOG", "false")) {
		router.Use(gin.Logger())
	}

	router.Use(longPollMiddleware())
	router.Use(dbMiddleware())
	api := router.Group("/api/v1/remote_clients")

	api.GET("/server_time", wgOrchestrator.handleGetServerTime)
	api.GET("/server_challenge", wgOrchestrator.handleGetServerChallenge)
	api.GET("/profile", wgOrchestrator.handleGetProfile)
	api.GET("/peer/:id", wgOrchestrator.handleGetPeer)
	api.GET("/events", wgOrchestrator.handleGetEvents)
	api.POST("/events/:k", wgOrchestrator.handlePostEvents)
	api.GET("/my_events", wgOrchestrator.handleGetPrivEvents)

	wgOrchestrator.router = router

	// TODO: store this somewhere so that its persistent
	wgOrchestrator.privateKey, wgOrchestrator.publicKey = remoteclients.GetKeysFromFile("/usr/local/pf/conf/wgorchestrator-auth.json")

	return wgOrchestrator, nil
}

func renderError(c *gin.Context, code int, err error) {
	log.LoggerWContext(c).Error("Got the following error while processing the request: " + err.Error())
	c.JSON(code, gin.H{"message": err.Error()})
}

func longPollFromContext(c *gin.Context) *golongpoll.LongpollManager {
	if v, ok := c.Get(LONG_POLL_CONTEXT_KEY); ok {
		return v.(*golongpoll.LongpollManager)
	} else {
		return nil
	}
}

func longPollMiddleware() gin.HandlerFunc {
	pubsub, err := golongpoll.StartLongpoll(golongpoll.Options{
		LoggingEnabled:     (sharedutils.EnvOrDefault("LOG_LEVEL", "") == "debug"),
		MaxEventBufferSize: 10,
		// Events stay for up to 5 minutes
		EventTimeToLiveSeconds: int(maxSessionIdleTime / time.Second),
	})
	sharedutils.CheckError(err)

	remoteclients.PublishNewClientsTo = pubsub

	return func(c *gin.Context) {
		c.Set(LONG_POLL_CONTEXT_KEY, pubsub)
		c.Next()
	}
}

func dbFromContext(c *gin.Context) *gorm.DB {
	if v, ok := c.Get(DB_CLIENT_CONTEXT_KEY); ok {
		return v.(*gorm.DB)
	} else {
		return nil
	}
}

func dbMiddleware() gin.HandlerFunc {
	onceSetup := sync.Once{}
	var gormdb *gorm.DB
	return func(c *gin.Context) {
		successDBConnect := false
		onceSetup.Do(func() {
			for !successDBConnect {
				var err error
				gormdb, err = gorm.Open("mysql", db.ReturnURIFromConfig(context.Background()))
				if err != nil {
					time.Sleep(time.Duration(5) * time.Second)
				} else {
					successDBConnect = true
				}
			}
		})

		if gormdb == nil {
			renderError(c, http.StatusInternalServerError, errors.New("Error creating connection to the database"))
			c.Abort()
			return
		}

		c.Set(DB_CLIENT_CONTEXT_KEY, gormdb)
		if err := gormdb.DB().Ping(); err != nil {
			log.LoggerWContext(c).Error(err.Error())
			renderError(c, http.StatusInternalServerError, errors.New("Error connecting to the database"))
			c.Abort()
		} else {
			c.Next()
		}
	}
}

func (h WgorchestratorHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	ctx := r.Context()

	defer panichandler.Http(ctx, w)

	if handledPath.MatchString(r.URL.Path) {
		h.router.ServeHTTP(w, r)
		return 0, nil
	} else {
		return h.Next.ServeHTTP(w, r)
	}

}
