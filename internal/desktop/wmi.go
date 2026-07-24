//go:build windows && (amd64 || arm64)

package desktop

import (
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/deploymenttheory/go-bindings-wmi/bindings/cim/cimv2"
	"github.com/deploymenttheory/go-bindings-wmi/runtime/wmi"
)

// wmiWorker owns a WMI Service on a dedicated, locked OS thread. The go-bindings
// -wmi Service is thread-affine (Connect calls runtime.LockOSThread), so every
// query and method call must run on the same goroutine; wmiWorker serializes
// them, mirroring the engine's own STA-thread model.
type wmiWorker struct {
	jobs chan func(*wmi.Service)
	quit chan struct{}
}

func newWMIWorker() (*wmiWorker, error) {
	w := &wmiWorker{jobs: make(chan func(*wmi.Service)), quit: make(chan struct{})}
	ready := make(chan error, 1)
	go w.run(ready)
	if err := <-ready; err != nil {
		return nil, err
	}
	return w, nil
}

func (w *wmiWorker) run(ready chan<- error) {
	runtime.LockOSThread()
	svc, err := wmi.Connect(`root\cimv2`)
	if err != nil {
		ready <- err
		return
	}
	defer svc.Close()
	ready <- nil
	for {
		select {
		case job := <-w.jobs:
			job(svc)
		case <-w.quit:
			return
		}
	}
}

func (w *wmiWorker) do(fn func(*wmi.Service)) error {
	done := make(chan struct{})
	select {
	case w.jobs <- func(svc *wmi.Service) { defer close(done); fn(svc) }:
		<-done
		return nil
	case <-w.quit:
		return ErrClosed
	}
}

func (w *wmiWorker) close() {
	select {
	case <-w.quit:
	default:
		close(w.quit)
	}
}

// withWMI lazily starts the WMI worker (once) and runs fn on its thread.
func (d *Desktop) withWMI(fn func(*wmi.Service) error) error {
	d.wmiMu.Lock()
	if d.wmi == nil {
		w, err := newWMIWorker()
		if err != nil {
			d.wmiMu.Unlock()
			return fmt.Errorf("failed to connect to WMI: %w", err)
		}
		d.wmi = w
	}
	worker := d.wmi
	d.wmiMu.Unlock()

	var fnErr error
	if err := worker.do(func(svc *wmi.Service) { fnErr = fn(svc) }); err != nil {
		return err
	}
	return fnErr
}

// QueryWMI runs a WQL query against an arbitrary WMI namespace (e.g.
// root\Microsoft\Windows\DeviceGuard or root\CIMV2\Security\MicrosoftVolumeEncryption)
// and returns the raw rows. The go-bindings-wmi Service is thread-affine —
// Connect locks the OS thread and Close unlocks it — so the whole Connect →
// Query → Close sequence runs on one dedicated goroutine. Used for the
// just-in-time device-health posture reads outside the long-lived root\cimv2
// worker.
func (d *Desktop) QueryWMI(namespace, wql string) ([]wmi.Row, error) {
	type result struct {
		rows []wmi.Row
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		svc, err := wmi.Connect(namespace)
		if err != nil {
			ch <- result{nil, fmt.Errorf("connect %s: %w", namespace, err)}
			return
		}
		defer svc.Close()
		rows, err := svc.Query(wql)
		ch <- result{rows, err}
	}()
	r := <-ch
	return r.rows, r.err
}

// ProcessInfo summarizes a running process.
type ProcessInfo struct {
	PID            uint32
	Name           string
	WorkingSetKB   uint64
	ThreadCount    uint32
	ParentPID      uint32
	ExecutablePath string
}

// ProcessList returns running processes via WMI, sorted by sortBy ("memory",
// "name", or "pid") and limited to at most limit entries (0 = no limit).
func (d *Desktop) ProcessList(sortBy string, limit int) ([]ProcessInfo, error) {
	var procs []ProcessInfo
	err := d.withWMI(func(svc *wmi.Service) error {
		rows, err := cimv2.QueryWin32Process(svc, "")
		if err != nil {
			return fmt.Errorf("query Win32_Process: %w", err)
		}
		procs = make([]ProcessInfo, 0, len(rows))
		for _, p := range rows {
			procs = append(procs, ProcessInfo{
				PID:            p.ProcessId,
				Name:           p.Name,
				WorkingSetKB:   p.WorkingSetSize / 1024,
				ThreadCount:    p.ThreadCount,
				ParentPID:      p.ParentProcessId,
				ExecutablePath: p.ExecutablePath,
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	switch sortBy {
	case "name":
		sort.Slice(procs, func(i, j int) bool {
			return strings.ToLower(procs[i].Name) < strings.ToLower(procs[j].Name)
		})
	case "pid":
		sort.Slice(procs, func(i, j int) bool { return procs[i].PID < procs[j].PID })
	default: // memory
		sort.Slice(procs, func(i, j int) bool { return procs[i].WorkingSetKB > procs[j].WorkingSetKB })
	}

	if limit > 0 && len(procs) > limit {
		procs = procs[:limit]
	}
	return procs, nil
}

// DiskInfo summarizes a logical disk.
type DiskInfo struct {
	Drive   string
	Volume  string
	SizeGB  float64
	FreeGB  float64
	UsedPct int
}

// SystemInfo is a snapshot of OS and hardware inventory.
type SystemInfo struct {
	Hostname      string
	OSCaption     string
	OSVersion     string
	OSArch        string
	BuildNumber   string
	LastBoot      string
	Manufacturer  string
	Model         string
	CPUName       string
	PhysicalCores uint32
	LogicalCPUs   uint32
	TotalMemoryMB uint64
	FreeMemoryMB  uint64
	Disks         []DiskInfo
}

// GetSystemInfo collects OS, computer-system, CPU, and disk inventory via WMI.
func (d *Desktop) GetSystemInfo() (SystemInfo, error) {
	var si SystemInfo
	err := d.withWMI(func(svc *wmi.Service) error {
		if os, err := cimv2.QueryOneWin32OperatingSystem(svc, ""); err == nil && os != nil {
			si.OSCaption = strings.TrimSpace(os.Caption)
			si.OSVersion = os.Version
			si.OSArch = os.OSArchitecture
			si.BuildNumber = os.BuildNumber
			si.LastBoot = os.LastBootUpTime
			if t, err := wmi.ParseDMTF(os.LastBootUpTime); err == nil {
				si.LastBoot = t.Format("2006-01-02 15:04:05 MST")
			}
			si.Hostname = os.CSName
			si.TotalMemoryMB = os.TotalVisibleMemorySize / 1024 // KB -> MB
			si.FreeMemoryMB = os.FreePhysicalMemory / 1024
		}
		if cs, err := cimv2.QueryOneWin32ComputerSystem(svc, ""); err == nil && cs != nil {
			if si.Hostname == "" {
				si.Hostname = cs.Name
			}
			si.Manufacturer = cs.Manufacturer
			si.Model = cs.Model
			si.LogicalCPUs = cs.NumberOfLogicalProcessors
		}
		if cpu, err := cimv2.QueryOneWin32Processor(svc, ""); err == nil && cpu != nil {
			si.CPUName = strings.TrimSpace(cpu.Name)
			si.PhysicalCores = cpu.NumberOfCores
		}
		disks, err := cimv2.QueryWin32LogicalDisk(svc, "DriveType = 3") // local disks
		if err == nil {
			for _, dk := range disks {
				sizeGB := float64(dk.Size) / (1 << 30)
				freeGB := float64(dk.FreeSpace) / (1 << 30)
				used := 0
				if dk.Size > 0 {
					used = int(100 * (dk.Size - dk.FreeSpace) / dk.Size)
				}
				si.Disks = append(si.Disks, DiskInfo{
					Drive: dk.DeviceID, Volume: dk.VolumeName,
					SizeGB: sizeGB, FreeGB: freeGB, UsedPct: used,
				})
			}
		}
		return nil
	})
	return si, err
}

// ServiceInfo summarizes a Windows service.
type ServiceInfo struct {
	Name        string
	DisplayName string
	State       string
	StartMode   string
	PID         uint32
}

// ListServices returns Windows services, optionally filtered by a name/display
// substring (case-insensitive).
func (d *Desktop) ListServices(filter string) ([]ServiceInfo, error) {
	var out []ServiceInfo
	needle := strings.ToLower(strings.TrimSpace(filter))
	err := d.withWMI(func(svc *wmi.Service) error {
		rows, err := cimv2.QueryWin32Service(svc, "")
		if err != nil {
			return fmt.Errorf("query Win32_Service: %w", err)
		}
		for _, s := range rows {
			if needle != "" &&
				!strings.Contains(strings.ToLower(s.Name), needle) &&
				!strings.Contains(strings.ToLower(s.DisplayName), needle) {
				continue
			}
			out = append(out, ServiceInfo{
				Name: s.Name, DisplayName: s.DisplayName,
				State: string(s.State), StartMode: string(s.StartMode), PID: s.ProcessId,
			})
		}
		return nil
	})
	return out, err
}

// ControlService starts, stops, or restarts a service by exact name
// (case-insensitive). Returns a human-readable result.
func (d *Desktop) ControlService(name, action string) (string, error) {
	var result string
	err := d.withWMI(func(svc *wmi.Service) error {
		row, err := cimv2.QueryOneWin32Service(svc, wmi.Where("Name = ?", name))
		if err != nil || row == nil {
			// Fall back to case-insensitive scan.
			rows, qerr := cimv2.QueryWin32Service(svc, "")
			if qerr != nil {
				return fmt.Errorf("query Win32_Service: %w", qerr)
			}
			for i := range rows {
				if strings.EqualFold(rows[i].Name, name) {
					row = &rows[i]
					break
				}
			}
			if row == nil {
				return fmt.Errorf("service %q not found", name)
			}
		}
		start := func() error {
			res, err := cimv2.Win32ServiceStartService(svc, row.WMIPath)
			if err != nil {
				return err
			}
			if res.ReturnValue != 0 {
				return fmt.Errorf("StartService returned %d", res.ReturnValue)
			}
			return nil
		}
		stop := func() error {
			res, err := cimv2.Win32ServiceStopService(svc, row.WMIPath)
			if err != nil {
				return err
			}
			if res.ReturnValue != 0 {
				return fmt.Errorf("StopService returned %d", res.ReturnValue)
			}
			return nil
		}
		switch action {
		case "start":
			if err := start(); err != nil {
				return err
			}
			result = fmt.Sprintf("Started service %q.", row.Name)
		case "stop":
			if err := stop(); err != nil {
				return err
			}
			result = fmt.Sprintf("Stopped service %q.", row.Name)
		case "restart":
			_ = stop()
			time.Sleep(1 * time.Second)
			if err := start(); err != nil {
				return err
			}
			result = fmt.Sprintf("Restarted service %q.", row.Name)
		default:
			return fmt.Errorf("unknown action %q", action)
		}
		return nil
	})
	return result, err
}

// HostFacts is device domain-join, OS-edition, and identity information used by
// the guardrails layer.
type HostFacts struct {
	PartOfDomain bool
	Domain       string
	OSSKU        uint32
	OSCaption    string
	Hostname     string
	Serial       string
}

// DomainAndSKU queries device domain-join, OS SKU, hostname, and BIOS serial via
// WMI.
func (d *Desktop) DomainAndSKU() (HostFacts, error) {
	var out HostFacts
	err := d.withWMI(func(svc *wmi.Service) error {
		if cs, e := cimv2.QueryOneWin32ComputerSystem(svc, ""); e == nil && cs != nil {
			out.PartOfDomain = cs.PartOfDomain
			out.Domain = cs.Domain
			out.Hostname = cs.Name
		}
		if o, e := cimv2.QueryOneWin32OperatingSystem(svc, ""); e == nil && o != nil {
			out.OSSKU = uint32(o.OperatingSystemSKU)
			out.OSCaption = strings.TrimSpace(o.Caption)
			if out.Hostname == "" {
				out.Hostname = o.CSName
			}
		}
		if b, e := cimv2.QueryOneWin32BIOS(svc, ""); e == nil && b != nil {
			out.Serial = strings.TrimSpace(b.SerialNumber)
		}
		return nil
	})
	return out, err
}

// closeWMI shuts down the WMI worker if it was started.
func (d *Desktop) closeWMI() {
	d.wmiMu.Lock()
	defer d.wmiMu.Unlock()
	if d.wmi != nil {
		d.wmi.close()
		d.wmi = nil
	}
}

// ProcessKill terminates processes matching pid (if non-zero) or whose name
// contains nameSubstr (case-insensitive). Returns the number of processes
// terminated.
func (d *Desktop) ProcessKill(pid uint32, nameSubstr string) (int, error) {
	killed := 0
	err := d.withWMI(func(svc *wmi.Service) error {
		var where string
		switch {
		case pid != 0:
			where = wmi.Where("ProcessId = ?", pid)
		case nameSubstr != "":
			// WMI LIKE for substring match.
			where = "Name LIKE '%" + strings.ReplaceAll(nameSubstr, "'", "''") + "%'"
		default:
			return fmt.Errorf("provide a pid or name to kill")
		}
		rows, err := cimv2.QueryWin32Process(svc, where)
		if err != nil {
			return fmt.Errorf("query Win32_Process: %w", err)
		}
		if len(rows) == 0 {
			return fmt.Errorf("no matching process")
		}
		for _, p := range rows {
			res, err := cimv2.Win32ProcessTerminate(svc, p.WMIPath, nil)
			if err != nil {
				return fmt.Errorf("terminate pid %d: %w", p.ProcessId, err)
			}
			if res.ReturnValue == 0 {
				killed++
			}
		}
		return nil
	})
	return killed, err
}
