package cmd

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/aau-network-security/kraaler"
	"github.com/aau-network-security/kraaler/store"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	workerAmount  int
	samplerName   string
	noResampling  bool
	dataDirectory string

	filterRespBodies string

	providerDomainFiles []string
)

var (
	samplersByName = map[string]store.Sampler{
		"uni": store.UniformSampler(),
		"pw":  store.PairSampler(2000),
	}
)

func ensureDir(dir string) error {
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		return err
	}

	return os.MkdirAll(dir, os.ModePerm)
}

var runCmd = &cobra.Command{
	Use: "run",
	Run: func(cmd *cobra.Command, args []string) {
		stopWithErr := func(err error) {
			log.Fatal(err)
		}

		ui := &runUI{}
		var logOpts []zap.Option

		logOpts = append(logOpts,
			zap.WrapCore(ui.Wrapper),
		)

		smpl, ok := samplersByName[samplerName]
		if !ok {
			stopWithErr(fmt.Errorf("unknown sampler: %s", samplerName))
		}

		urlOpts := []store.URLStoreOpt{store.WithSampler(smpl)}

		if noResampling {
			urlOpts = append(urlOpts, store.WithNoResampling())
		}

		screenshotDir := filepath.Join(dataDirectory, "screenshots")
		bodiesDir := filepath.Join(dataDirectory, "response_bodies")
		for _, dir := range []string{
			dataDirectory,
			screenshotDir,
			bodiesDir,
		} {
			if err := ensureDir(dir); err != nil {
				stopWithErr(err)
			}
		}

		logger, err := newLogger(logOpts...)
		if err != nil {
			stopWithErr(err)
		}
		defer logger.Sync()

		var providers []kraaler.URLProvider
		for _, path := range providerDomainFiles {
			p, err := kraaler.NewDomainFileProvider(path, &kraaler.DomainFileProviderConfig{
				Logger: logger,
			})
			if err != nil {
				stopWithErr(err)
			}

			providers = append(providers, p)
		}

		if len(providers) == 0 {
			stopWithErr(fmt.Errorf("need one or more providers"))
		}

		dbFile := filepath.Join(dataDirectory, "kraaler.db")
		db, err := sql.Open("sqlite3", dbFile)
		if err != nil {
			stopWithErr(err)
		}

		us, err := store.NewURLStore(db, urlOpts...)
		if err != nil {
			stopWithErr(err)
		}

		for _, p := range providers {
			us.Consume(p)
		}

		ps, err := store.NewStore(db, bodiesDir, screenshotDir)
		if err != nil {
			stopWithErr(err)
		}

		wc, err := kraaler.NewWorkerController(context.Background(), kraaler.WorkerControllerConfig{
			URLStore:  us,
			PageStore: ps,
			Logger:    logger,
		})
		if err != nil {
			stopWithErr(err)
		}

		time.Sleep(5 * time.Second)

		for i := 0; i < workerAmount; i++ {
			err := wc.AddWorker()
			if err != nil {
				logger.Info("add_worker_error", zap.String("err", err.Error()))
			}
		}

		if err := ui.Show(); err != nil {
			fmt.Println("Unexpected error showing ui:", err)
		}

		sigs := make(chan os.Signal, 1)
		done := make(chan struct{}, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

		go func() {
			<-sigs
			wc.Close()
			done <- struct{}{}
		}()

		<-done
	},
}

func newLogger(opts ...zap.Option) (*zap.Logger, error) {
	cfg := zap.NewProductionConfig()
	cfg.OutputPaths = []string{
		"./crawled-data/log",
	}
	return cfg.Build(opts...)
}

func init() {
	runCmd.Flags().IntVarP(&workerAmount, "workers", "n", 1, "Amount of workers in the pool")
	runCmd.Flags().StringVar(&samplerName, "sampler", "uni", "The type of sampler used for prioritizing URLs")
	runCmd.Flags().BoolVarP(&noResampling, "unique", "u", false, "Only crawl URLs once")
	runCmd.Flags().StringVarP(&dataDirectory, "data-dir", "o", "crawled-data", "Directory to output crawled information")

	runCmd.Flags().StringVar(&filterRespBodies, "filter-resp-bodies-ct", "", "Filter response bodies using regexp on content type")

	runCmd.Flags().StringSliceVar(&providerDomainFiles, "provider-domain-file", []string{}, "Read file and provide a series of URLs based on the domains found in the file")

	RootCmd.AddCommand(runCmd)
}
