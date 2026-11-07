// Windows service + console host for the vTPM2 software TPM 2.0 engine.
//
// Runs either as a registered Windows service ("vTPM2") or interactively from the
// console. In both modes it hosts a single go-sdk-vtpm2 TPM engine, persists state,
// exposes raw TPM commands over HTTP, and serves an HTTP dashboard (GUI).

package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/windows/svc"

	"github.com/vtpm2/service/internal/host"
)

const serviceName = "vTPM2"

// engine is the single TPM host shared by service and console modes.
var engine *host.Host

func initEngine() {
	if engine == nil {
		cfg := host.LoadConfig()
		engine = host.NewFromConfig(cfg)
		log.Printf("vTPM2 config: stateDir=%s http=%s:%d", cfg.StateDir, cfg.HTTPBind, cfg.HTTPPort)
	}
}

type serviceHandler struct{}

func (h *serviceHandler) Execute(args []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown

	s <- svc.Status{State: svc.StartPending, Accepts: accepted}

	initEngine()
	if err := engine.Start(); err != nil {
		log.Printf("vTPM2 service start failed: %v", err)
		s <- svc.Status{State: svc.Stopped}
		return false, 1
	}
	defer engine.Stop()

	s <- svc.Status{State: svc.Running, Accepts: accepted}

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				s <- svc.Status{State: svc.Running, Accepts: accepted}
			case svc.Stop, svc.Shutdown:
				s <- svc.Status{State: svc.Stopped}
				return false, 0
			default:
				return false, 0
			}
		}
	}
}

func runService() error {
	return svc.Run(serviceName, &serviceHandler{})
}

func runConsole() error {
	log.Println("vTPM2 running in console mode. Press Ctrl+C to stop.")
	initEngine()
	if err := engine.Start(); err != nil {
		return err
	}
	defer engine.Stop()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	log.Println("vTPM2 console shutting down.")
	return nil
}

func main() {
	isService, err := svc.IsWindowsService()
	if err != nil {
		log.Fatalf("failed to detect service mode: %v", err)
	}
	if isService {
		if err := runService(); err != nil {
			log.Fatalf("service exited: %v", err)
		}
		return
	}
	if err := runConsole(); err != nil {
		log.Fatalf("console exited: %v", err)
	}
}
