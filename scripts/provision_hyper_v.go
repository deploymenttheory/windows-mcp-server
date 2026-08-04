//go:build windows

// Command provision_hyper_v brings a Hyper-V lab VM to a test-ready state for
// this MCP server, so the shipped stdio binary — full guardrails, enforcing
// --policy-config, real device signals — can be tested against a clean,
// disposable Windows desktop instead of the developer's machine.
//
// It automates the guest customization that was first performed by hand
// (2026-08-04). The VM itself must already exist and be running with an
// auto-logged-in interactive desktop (weave-managed; see HANDOFF-vm-testing.md
// for VM creation and the separate HTTP-bridge provisioning in
// D:\payload\provision-win11-mcp.ps1, which this program does not cover).
// Everything here runs over PowerShell Direct, so no network path to the guest
// is required, and every step is idempotent — re-running against an already
// provisioned guest is safe.
//
// Steps, in order:
//
//  1. baseline    — guest reachable, AMD64, enough disk, outbound network
//  2. exec-policy — RemoteSigned, or the interactive runner script cannot execute
//  3. go          — install the Go toolchain at C:\go and put it on the machine PATH
//  4. payload     — git archive HEAD → copy into the guest → C:\mcp\src, plus the
//     interactive runner C:\mcp\run-interactive.ps1
//  5. build       — go build ./... and the untagged product binary
//     C:\mcp\windows-mcp-server-stdio.exe (no conformance HTTP host)
//  6. verify      — the runner lands in an interactive desktop session,
//     `policy check` admits the device, and a fast package test passes
//
// The interactive runner exists because PowerShell Direct sessions have no
// desktop: UIA-dependent tests and the stdio server must run in the logged-on
// user's session, so the runner dispatches commands there via a one-shot
// scheduled task and returns the captured output.
//
// Usage, from an elevated host shell with the Hyper-V PowerShell module:
//
//	go run ./scripts/provision_hyper_v.go [-vm win11-mcp] [-user weave] [-pass weave] [-go-version 1.26.5] [-repo .]
package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"
)

// runInteractivePS1 is installed into the guest as C:\mcp\run-interactive.ps1.
//
// It writes a per-run script file (avoids all quoting concerns in the task
// action, and leaves every run inspectable under C:\mcp\runs), registers a
// one-shot scheduled task whose principal is the interactive logon of -User,
// starts it, polls for the exit marker, then returns "EXIT=<code>" followed by
// the captured output. The per-run script extends PATH itself because a
// scheduled task starts from the bare logon environment.
const runInteractivePS1 = `param(
    [Parameter(Mandatory = $true)][string]$Command,
    [string]$WorkDir = 'C:\mcp',
    [string]$User = 'weave',
    [int]$TimeoutSec = 900
)

$ErrorActionPreference = 'Stop'
$runId = [guid]::NewGuid().ToString('N').Substring(0, 12)
$runDir = 'C:\mcp\runs'
if (-not (Test-Path $runDir)) { New-Item -ItemType Directory -Path $runDir | Out-Null }
$log = Join-Path $runDir ($runId + '.log')
$exitFile = Join-Path $runDir ($runId + '.exit')
$runScript = Join-Path $runDir ($runId + '.ps1')

$lines = @(
    '$ErrorActionPreference = ''Continue''',
    '$env:Path += '';C:\go\bin;'' + $env:USERPROFILE + ''\go\bin''',
    ('Set-Location ''' + $WorkDir + ''''),
    ('& { ' + $Command + ' } *> ''' + $log + ''''),
    ('Set-Content -Path ''' + $exitFile + ''' -Value ' + '$LASTEXITCODE')
)
Set-Content -Path $runScript -Value ($lines -join [Environment]::NewLine) -Encoding UTF8

$taskName = 'MCP-Lab-Run-' + $runId
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $runScript + '"')
$principal = New-ScheduledTaskPrincipal -UserId $User -LogonType Interactive
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Seconds ($TimeoutSec + 60))
Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null

try {
    Start-ScheduledTask -TaskName $taskName
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while (-not (Test-Path $exitFile)) {
        if ((Get-Date) -gt $deadline) {
            Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            Write-Output ('TIMEOUT after ' + $TimeoutSec + ' s; partial output:')
            if (Test-Path $log) { Get-Content $log }
            return
        }
        Start-Sleep -Seconds 2
    }
    Write-Output ('EXIT=' + (Get-Content $exitFile | Select-Object -First 1))
    if (Test-Path $log) { Get-Content $log }
} finally {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
}
`

type lab struct {
	vm        string
	user      string
	pass      string
	repo      string
	goVersion string
}

var errStep = errors.New("provision step failed")

func main() {
	l := lab{}
	flag.StringVar(&l.vm, "vm", "win11-mcp", "Hyper-V VM name")
	flag.StringVar(&l.user, "user", "weave", "guest local admin user (must be the auto-logged-in interactive user)")
	flag.StringVar(&l.pass, "pass", "weave", "guest local admin password")
	flag.StringVar(&l.repo, "repo", ".", "repo root to provision from (git archive HEAD)")
	flag.StringVar(&l.goVersion, "go-version", "1.26.5", "Go toolchain version to install in the guest")
	flag.Parse()

	if _, err := os.Stat(filepath.Join(l.repo, "go.mod")); err != nil {
		fatal(fmt.Errorf("-repo %q does not look like the repo root: %w", l.repo, err))
	}

	steps := []struct {
		name    string
		timeout time.Duration
		run     func(context.Context) error
	}{
		{"baseline", 3 * time.Minute, l.baseline},
		{"exec-policy", 2 * time.Minute, l.execPolicy},
		{"go", 10 * time.Minute, l.installGo},
		{"payload", 5 * time.Minute, l.copyPayload},
		{"build", 15 * time.Minute, l.build},
		{"verify", 25 * time.Minute, l.verify},
	}
	for _, s := range steps {
		fmt.Printf("== %s\n", s.name)
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
		err := s.run(ctx)
		cancel()
		if err != nil {
			fatal(fmt.Errorf("%w: %s: %w", errStep, s.name, err))
		}
		fmt.Printf("== %s ok (%s)\n", s.name, time.Since(start).Round(time.Second))
	}
	fmt.Println("guest is test-ready: C:\\mcp\\src, C:\\mcp\\windows-mcp-server-stdio.exe, C:\\mcp\\run-interactive.ps1")
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "provision_hyper_v:", err)
	os.Exit(1)
}

// baseline proves the guest is reachable over PowerShell Direct and fit to
// provision: right architecture for the toolchain zip, enough disk for
// toolchain + source + build cache, and outbound network for go.dev and the
// module proxy.
func (l *lab) baseline(ctx context.Context) error {
	script := `$ErrorActionPreference = 'Stop'
$arch = $env:PROCESSOR_ARCHITECTURE
if ($arch -ne 'AMD64') { throw ('unsupported guest arch: ' + $arch) }
$freeGB = [math]::Round((Get-PSDrive C).Free / 1GB, 1)
if ($freeGB -lt 10) { throw ('not enough free disk: ' + $freeGB + ' GB') }
$net = (Invoke-WebRequest -Uri 'https://go.dev' -UseBasicParsing -TimeoutSec 15 -Method Head).StatusCode
Write-Output ('hostname=' + $env:COMPUTERNAME + ' arch=' + $arch + ' freeGB=' + $freeGB + ' net=' + $net)`
	return l.guest(ctx, script)
}

// execPolicy allows local scripts to run. A clean Windows install ships
// Restricted, which blocks the interactive runner outright (learned the hard
// way: the first runner invocation failed with a SecurityError).
func (l *lab) execPolicy(ctx context.Context) error {
	return l.guest(ctx, `Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
Write-Output ('execution policy: ' + (Get-ExecutionPolicy -Scope LocalMachine))`)
}

// installGo downloads the Go zip inside the guest and extracts it to C:\go.
//
// Extraction deliberately uses .NET ZipFile: the guest's bundled bsdtar fails
// to create the tree under C:\ from this archive ("Can't create ...: No such
// file or directory" for every entry), while ZipFile handles it reliably.
func (l *lab) installGo(ctx context.Context) error {
	script := `$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if (-not (Test-Path 'C:\mcp')) { New-Item -ItemType Directory -Path 'C:\mcp' | Out-Null }
if (Test-Path 'C:\go\bin\go.exe') {
    Write-Output ('already installed: ' + (& C:\go\bin\go.exe version))
} else {
    $zip = 'C:\mcp\go` + l.goVersion + `.windows-amd64.zip'
    if (-not (Test-Path $zip)) {
        Invoke-WebRequest -Uri 'https://go.dev/dl/go` + l.goVersion + `.windows-amd64.zip' -OutFile $zip -UseBasicParsing
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zip, 'C:\')
    Write-Output (& C:\go\bin\go.exe version)
}
$mp = [Environment]::GetEnvironmentVariable('Path', 'Machine')
if ($mp -notlike '*C:\go\bin*') {
    [Environment]::SetEnvironmentVariable('Path', $mp.TrimEnd(';') + ';C:\go\bin;C:\Users\` + psq(l.user) + `\go\bin', 'Machine')
    Write-Output 'machine PATH updated'
}`
	return l.guest(ctx, script)
}

// copyPayload ships the source and the interactive runner into the guest.
//
// The source is `git archive HEAD` — the committed tree, not the working copy —
// zipped on the host and copied over a PowerShell Direct session, so the guest
// needs neither git nor network access to the repo host. An existing C:\mcp\src
// is renamed aside rather than deleted, so a half-finished previous copy can
// never masquerade as the current tree (clean up C:\mcp\src-old-* manually).
func (l *lab) copyPayload(ctx context.Context) error {
	tmp, err := os.MkdirTemp("", "winmcp-provision-")
	if err != nil {
		return fmt.Errorf("temp dir: %w", err)
	}
	defer os.RemoveAll(tmp)

	zipPath := filepath.Join(tmp, "src.zip")
	git := exec.CommandContext(ctx, "git", "-C", l.repo, "archive", "--format=zip", "-o", zipPath, "HEAD")
	if out, gitErr := git.CombinedOutput(); gitErr != nil {
		return fmt.Errorf("git archive: %w: %s", gitErr, strings.TrimSpace(string(out)))
	}
	runnerPath := filepath.Join(tmp, "run-interactive.ps1")
	if err := os.WriteFile(runnerPath, []byte(runInteractivePS1), 0o600); err != nil {
		return fmt.Errorf("write runner: %w", err)
	}

	inGuest := `$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if (Test-Path 'C:\mcp\src') {
    Rename-Item 'C:\mcp\src' ('C:\mcp\src-old-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
}
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::ExtractToDirectory('C:\mcp\src.zip', 'C:\mcp\src')
Unblock-File 'C:\mcp\run-interactive.ps1'
Write-Output ('extracted ' + (Get-ChildItem 'C:\mcp\src' | Measure-Object).Count + ' top-level entries; runner installed')`

	host := `$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$c = New-Object pscredential '` + psq(l.user) + `',(ConvertTo-SecureString '` + psq(l.pass) + `' -AsPlainText -Force)
$s = New-PSSession -VMName '` + psq(l.vm) + `' -Credential $c
try {
    Copy-Item -ToSession $s '` + psq(zipPath) + `' -Destination 'C:\mcp\src.zip'
    Copy-Item -ToSession $s '` + psq(runnerPath) + `' -Destination 'C:\mcp\run-interactive.ps1'
    Invoke-Command -Session $s -ScriptBlock ([scriptblock]::Create(` + psB64(inGuest) + `))
} finally {
    Remove-PSSession $s
}`
	return l.host(ctx, host)
}

// build compiles the whole tree and the untagged product binary in the guest.
// Native stderr becomes PowerShell error records inside a remote session, and
// `go mod download` reports progress on stderr, so the go invocations redirect
// 2>&1 and gate on $LASTEXITCODE instead of running under EAP Stop.
func (l *lab) build(ctx context.Context) error {
	script := `$ErrorActionPreference = 'Continue'
Set-Location C:\mcp\src
$env:Path += ';C:\go\bin'
$out = go mod download 2>&1
if ($LASTEXITCODE -ne 0) { $out | Write-Output; throw 'go mod download failed' }
$out = go build ./... 2>&1
if ($LASTEXITCODE -ne 0) { $out | Write-Output; throw 'go build ./... failed' }
$out = go build -o C:\mcp\windows-mcp-server-stdio.exe ./cmd/windows-mcp-server 2>&1
if ($LASTEXITCODE -ne 0) { $out | Write-Output; throw 'product binary build failed' }
Write-Output ('build ok: ' + [math]::Round((Get-Item C:\mcp\windows-mcp-server-stdio.exe).Length / 1MB, 1) + ' MB')`
	return l.guest(ctx, script)
}

// verify proves the three properties the tests depend on: the runner reaches a
// real interactive desktop session (not session 0), the product binary's
// `policy check` admits this device from that session, and the toolchain can
// compile and pass a fast package test.
func (l *lab) verify(ctx context.Context) error {
	u := psq(l.user)
	script := `$ErrorActionPreference = 'Stop'
$probe = & C:\mcp\run-interactive.ps1 -User '` + u + `' -Command 'Write-Output (''session='' + (Get-Process -Id $pid).SessionId + '' interactive='' + [Environment]::UserInteractive)' -TimeoutSec 180
$probeText = $probe -join ' '
Write-Output ('runner: ' + $probeText)
if ($probeText -notmatch 'interactive=True') { throw 'runner did not reach an interactive desktop session' }
if (($probeText -match 'session=(\d+)') -and ($Matches[1] -eq '0')) { throw 'runner landed in session 0' }

$pc = & C:\mcp\run-interactive.ps1 -User '` + u + `' -Command 'C:\mcp\windows-mcp-server-stdio.exe policy check 2>&1' -TimeoutSec 300
$pcText = $pc -join ' '
if ($pcText -notmatch '"admit": true') { Write-Output $pcText; throw 'policy check did not admit the device' }
Write-Output 'policy check: device admitted from the interactive session'

$t = & C:\mcp\run-interactive.ps1 -User '` + u + `' -Command 'go test ./pkg/windows/... -count=1 2>&1' -WorkDir 'C:\mcp\src' -TimeoutSec 900
$tText = $t -join ' '
if ($tText -notmatch 'EXIT=0') { Write-Output $tText; throw 'go test ./pkg/windows failed' }
Write-Output 'go test ./pkg/windows: ok'`
	return l.guest(ctx, script)
}

// guest runs a script inside the VM over PowerShell Direct and streams its
// output to stdout. The inner script travels base64-encoded so no quoting in it
// can interact with the host shell or the outer script. Progress preference is
// silenced on both sides: remote progress records otherwise come back as CLIXML
// noise interleaved with the real output.
func (l *lab) guest(ctx context.Context, inner string) error {
	inner = "$ProgressPreference = 'SilentlyContinue'\n" + inner
	outer := `$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$c = New-Object pscredential '` + psq(l.user) + `',(ConvertTo-SecureString '` + psq(l.pass) + `' -AsPlainText -Force)
Invoke-Command -VMName '` + psq(l.vm) + `' -Credential $c -ScriptBlock ([scriptblock]::Create(` + psB64(inner) + `))`
	return l.host(ctx, outer)
}

// host runs a script in Windows PowerShell on the host via -EncodedCommand,
// which sidesteps every command-line quoting concern (the same reason the
// server itself invokes PowerShell that way).
//
// PSModulePath is dropped from the child environment: when this program is
// launched from pwsh 7, the inherited value points at pwsh's module roots and
// hides 5.1's System32 modules, so even ConvertTo-SecureString fails to load.
// With the variable absent, powershell.exe reconstructs its own default.
func (l *lab) host(ctx context.Context, script string) error {
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encodePS(script))
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(kv), "PSMODULEPATH=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("powershell: %w", err)
	}
	return nil
}

// psq quotes a value for inclusion inside a single-quoted PowerShell string.
func psq(s string) string { return strings.ReplaceAll(s, "'", "''") }

// psB64 renders a PowerShell expression that decodes to the given script text.
func psB64(script string) string {
	u := utf16.Encode([]rune(script))
	b := make([]byte, 2*len(u))
	for i, cu := range u {
		binary.LittleEndian.PutUint16(b[2*i:], cu)
	}
	return "[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('" + base64.StdEncoding.EncodeToString(b) + "'))"
}

// encodePS produces the -EncodedCommand form of a script: base64 over UTF-16LE.
func encodePS(script string) string {
	u := utf16.Encode([]rune(script))
	b := make([]byte, 2*len(u))
	for i, cu := range u {
		binary.LittleEndian.PutUint16(b[2*i:], cu)
	}
	return base64.StdEncoding.EncodeToString(b)
}
