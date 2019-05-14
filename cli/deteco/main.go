package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	flags "github.com/jessevdk/go-flags"
	"github.com/karlseguin/ccache"
	"github.com/kazeburo/deteco/deteco"
	ss "github.com/lestrrat/go-server-starter-listener"
	"go.uber.org/zap"
)

// Version by Makefile
var Version string

type cmdOpts struct {
	Version        bool          `short:"v" long:"version" description:"Show version"`
	Listen         string        `long:"listen" default:"127.0.0.1:8080" description:"Address to listen to."`
	TomlPath       string        `long:"conf" required:"true" description:"path to services toml file"`
	DryRun         bool          `long:"dry-run" description:"check services toml file only"`
	JWTFreshness   time.Duration `long:"jwt-freshness" default:"1h" description:"time in seconds to allow generated jwt tokens"`
	AuthEndpoint   string        `long:"auth-endpoint" default:"auth" description:"auth endpoint path"`
	CacheSize      int64         `long:"cache-size" default:"1000" description:"max number of items in cache"`
	CachePruneSize uint32        `long:"prune-size" default:"100" description:"the number of cached items to prune when we hit CacheSize"`
}

func printVersion() {
	fmt.Printf(`deteco %s
Compiler: %s %s
`,
		Version,
		runtime.Compiler,
		runtime.Version())
}

func main() {
	os.Exit(_main())
}

func _main() int {
	opts := cmdOpts{}
	psr := flags.NewParser(&opts, flags.Default)
	_, err := psr.Parse()
	if err != nil {
		return 1
	}
	if opts.Version {
		printVersion()
		return 0
	}

	logger, _ := zap.NewProduction()

	conf, err := deteco.NewConf(opts.TomlPath, logger)
	if err != nil {
		logger.Fatal("Failed read toml", zap.Error(err))
	}

	if opts.DryRun {
		logger.Info("Loaded toml file successfully", zap.Int("services loaded", len(conf.Services)))
		return 0
	}

	cache := ccache.New(ccache.Configure().MaxSize(opts.CacheSize).ItemsToPrune(opts.CachePruneSize))

	handler, err := deteco.NewHandler(
		conf,
		opts.JWTFreshness,
		cache,
		logger,
	)
	if err != nil {
		logger.Fatal("Failed init handler", zap.Error(err))
	}

	m := mux.NewRouter()
	m.HandleFunc("/", handler.Hello())
	m.HandleFunc("/live", handler.Hello())
	m.HandleFunc("/"+opts.AuthEndpoint, handler.Auth())

	s := &http.Server{
		Handler:        m,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	idleConnsClosed := make(chan struct{})
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGTERM)
		<-sigChan
		if es := s.Shutdown(context.Background()); es != nil {
			logger.Warn("Shutdown error", zap.Error(es))
		}
		close(idleConnsClosed)
	}()

	l, err := ss.NewListener()
	if l == nil || err != nil {
		// Fallback if not running under Server::Starter
		l, err = net.Listen("tcp", opts.Listen)
		if err != nil {
			logger.Error("Failed to listen to port", zap.String("listen", opts.Listen))
			return 1
		}
	}

	if err := s.Serve(l); err != http.ErrServerClosed {
		logger.Error("Error in Serve", zap.Error(err))
		return 1
	}

	<-idleConnsClosed
	return 0

}
