package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
)

var errCancelled = errors.New("installation cancelled")

const maxInstallerLogLine = 4096

var nonPublicIPv4Prefixes = [...]netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
}

func installerContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// The installer owns the alternate screen only while its interactive UI runs.
// Preserve ISIG so Ctrl+C also cancels a long-running Compose build.
func enterTerminal(input, output *os.File) (func(), error) {
	stty := exec.Command("stty", "-g")
	stty.Stdin = input
	saved, err := stty.Output()
	if err != nil {
		return nil, fmt.Errorf("read terminal settings: %w", err)
	}
	set := exec.Command("stty", "-icanon", "-echo", "-ixon", "min", "1", "time", "0")
	set.Stdin = input
	if output, err := set.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("enable keyboard input: %w: %s", err, strings.TrimSpace(string(output)))
	}
	var once sync.Once
	restore := func() {
		once.Do(func() {
			_, _ = io.WriteString(output, "\x1b[?25h\x1b[?1049l")
			reset := exec.Command("stty", strings.TrimSpace(string(saved)))
			reset.Stdin = input
			_ = reset.Run()
		})
	}
	if _, err := io.WriteString(output, "\x1b[?1049h\x1b[?25l"); err != nil {
		restore()
		return nil, err
	}
	return restore, nil
}

type keyKind uint8

const (
	keyCharacter keyKind = iota
	keyEnter
	keyBackspace
	keyUp
	keyDown
	keyLeft
	keyRight
	keyTab
	keyEscape
)

type keyPress struct {
	kind keyKind
	char byte
}

type wizard struct {
	out                 io.Writer
	inputFile           *os.File
	bytes               chan byte
	done                chan struct{}
	resize              chan os.Signal
	resizeDone          chan struct{}
	mu                  sync.Mutex
	width               int
	height              int
	stepNo              int
	title               string
	notice              string
	fields              [2]string
	configPage          string
	tlsSelection        int
	hysteriaFields      [3]string
	hysteriaSuggestedIP string
	focus               int
	choice              bool
	choiceRaw           string
	config              configuration
	logs                []string
	partial             string
	noColor             bool
}

func newWizard(input io.Reader, output io.Writer) *wizard {
	w := &wizard{
		out:                 output,
		bytes:               make(chan byte),
		done:                make(chan struct{}),
		width:               100,
		height:              30,
		choice:              true,
		hysteriaSuggestedIP: suggestPublicIPv4(),
		noColor:             os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb",
	}
	if file, ok := input.(*os.File); ok {
		w.inputFile = file
		w.width, w.height = terminalSize(file)
		w.resize = make(chan os.Signal, 1)
		w.resizeDone = make(chan struct{})
		signal.Notify(w.resize, syscall.SIGWINCH)
		go w.watchResize()
	}
	go w.readBytes(input)
	return w
}

func (w *wizard) close() {
	close(w.done)
	if w.resize != nil {
		signal.Stop(w.resize)
		<-w.resizeDone
	}
}

func terminalSize(input *os.File) (int, int) {
	cmd := exec.Command("stty", "size")
	cmd.Stdin = input
	data, err := cmd.Output()
	if err != nil {
		return 100, 30
	}
	parts := strings.Fields(string(data))
	if len(parts) != 2 {
		return 100, 30
	}
	height, errH := strconv.Atoi(parts[0])
	width, errW := strconv.Atoi(parts[1])
	if errH != nil || errW != nil || width < 1 || height < 1 {
		return 100, 30
	}
	return width, height
}

// Suggest an address only when the host has exactly one public IPv4 address.
// Private Docker and LAN addresses are never offered as the VPS endpoint.
func suggestPublicIPv4() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	var addresses []netip.Addr
	for _, device := range interfaces {
		if device.Flags&net.FlagUp == 0 || device.Flags&net.FlagLoopback != 0 {
			continue
		}
		assigned, err := device.Addrs()
		if err != nil {
			continue
		}
		for _, value := range assigned {
			if network, ok := value.(*net.IPNet); ok {
				if address, ok := netip.AddrFromSlice(network.IP); ok {
					addresses = append(addresses, address.Unmap())
				}
			}
		}
	}
	return uniquePublicIPv4(addresses)
}

func uniquePublicIPv4(addresses []netip.Addr) string {
	var result netip.Addr
	for _, address := range addresses {
		if !address.Is4() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLinkLocalUnicast() {
			continue
		}
		excluded := false
		for _, prefix := range nonPublicIPv4Prefixes {
			if prefix.Contains(address) {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}
		if result.IsValid() && result != address {
			return ""
		}
		result = address
	}
	if !result.IsValid() {
		return ""
	}
	return result.String()
}

func (w *wizard) watchResize() {
	defer close(w.resizeDone)
	for {
		select {
		case <-w.done:
			return
		case <-w.resize:
			width, height := terminalSize(w.inputFile)
			w.mu.Lock()
			w.width, w.height = width, height
			w.renderLocked()
			w.mu.Unlock()
		}
	}
}

func (w *wizard) readBytes(input io.Reader) {
	defer close(w.bytes)
	buffer := make([]byte, 1)
	for {
		if _, err := io.ReadFull(input, buffer); err != nil {
			return
		}
		select {
		case w.bytes <- buffer[0]:
		case <-w.done:
			return
		}
	}
}

func (w *wizard) nextByte(ctx context.Context) (byte, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case b, ok := <-w.bytes:
		if !ok {
			return 0, fmt.Errorf("terminal input ended: %w", io.EOF)
		}
		return b, nil
	}
}

func (w *wizard) key(ctx context.Context) (keyPress, error) {
	b, err := w.nextByte(ctx)
	if err != nil {
		return keyPress{}, err
	}
	switch b {
	case '\r', '\n':
		return keyPress{kind: keyEnter}, nil
	case '\t':
		return keyPress{kind: keyTab}, nil
	case 8, 127:
		return keyPress{kind: keyBackspace}, nil
	case 27:
		timer := time.NewTimer(50 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return keyPress{}, ctx.Err()
		case <-timer.C:
			return keyPress{kind: keyEscape}, nil
		case next, ok := <-w.bytes:
			if !ok || next != '[' {
				return keyPress{kind: keyEscape}, nil
			}
		}
		third, err := w.nextByte(ctx)
		if err != nil {
			return keyPress{kind: keyEscape}, nil
		}
		switch third {
		case 'A':
			return keyPress{kind: keyUp}, nil
		case 'B':
			return keyPress{kind: keyDown}, nil
		case 'C':
			return keyPress{kind: keyRight}, nil
		case 'D':
			return keyPress{kind: keyLeft}, nil
		}
		return keyPress{kind: keyEscape}, nil
	default:
		return keyPress{kind: keyCharacter, char: b}, nil
	}
}

func (w *wizard) step(number int, title string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.stepNo, w.title, w.notice = number, title, ""
	w.renderLocked()
}

func (w *wizard) message(message string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.notice = message
	w.renderLocked()
}

func (w *wizard) review(cfg configuration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.stepNo, w.title, w.config, w.notice = 3, "Review installation", cfg, ""
	w.choice, w.choiceRaw = true, ""
	w.renderLocked()
}

func (w *wizard) hysteria(ctx context.Context, root string, cfg configuration) (configuration, error) {
	w.mu.Lock()
	w.configPage = "hysteria-choice"
	w.focus = 0
	w.tlsSelection = 0
	if cfg.hysteriaEnabled {
		if cfg.hysteriaMode == "self-signed" {
			w.tlsSelection = 1
		} else if cfg.hysteriaMode == "legacy" {
			w.tlsSelection = -1
		} else {
			w.tlsSelection = 2
		}
	}
	w.hysteriaFields = [3]string{"", "", cfg.hysteriaServerName}
	w.title = "Hysteria 2 TLS"
	w.notice = ""
	if w.tlsSelection == -1 {
		w.notice = "Existing Hysteria 2 setup: select a TLS mode before continuing."
	}
	w.renderLocked()
	w.mu.Unlock()

	for {
		key, err := w.key(ctx)
		if err != nil {
			return configuration{}, err
		}
		w.mu.Lock()
		if (w.width < 64 || w.height < 22) && key.kind != keyEscape {
			w.notice = "Enlarge the terminal before continuing."
			w.renderLocked()
			w.mu.Unlock()
			continue
		}
		if key.kind == keyEscape {
			w.mu.Unlock()
			return configuration{}, errCancelled
		}
		switch w.configPage {
		case "hysteria-choice":
			switch key.kind {
			case keyUp, keyLeft:
				if w.tlsSelection < 0 {
					w.tlsSelection = 2
				} else {
					w.tlsSelection = (w.tlsSelection + 2) % 3
				}
			case keyDown, keyRight, keyTab:
				w.tlsSelection = (w.tlsSelection + 1) % 3
			case keyCharacter:
				if key.char >= '1' && key.char <= '3' {
					w.tlsSelection = int(key.char - '1')
				}
			case keyEnter:
				switch w.tlsSelection {
				case 0:
					cfg.hysteriaEnabled = false
					w.mu.Unlock()
					return cfg, nil
				case 1:
					cfg.hysteriaEnabled = true
					cfg.hysteriaMode = "self-signed"
					cfg.hysteriaServerName = ""
					w.configPage = "hysteria-ip"
					w.hysteriaFields[0] = cfg.hysteriaCertIP
				case 2:
					cfg.hysteriaEnabled = true
					cfg.hysteriaMode = "custom"
					cfg.hysteriaCertIP = ""
					w.configPage = "hysteria-custom"
					w.focus = 0
				default:
					w.notice = "Select mkcert or your certificate for the existing Hysteria 2 setup."
				}
			}
		case "hysteria-ip":
			switch key.kind {
			case keyBackspace:
				w.hysteriaFields[0] = strings.TrimSuffix(w.hysteriaFields[0], lastRune(w.hysteriaFields[0]))
			case keyCharacter:
				if (key.char >= '0' && key.char <= '9' || key.char == '.') && len(w.hysteriaFields[0]) < 15 {
					w.hysteriaFields[0] += string(key.char)
				}
			case keyEnter:
				selectedIP := w.hysteriaFields[0]
				if selectedIP == "" {
					selectedIP = w.hysteriaSuggestedIP
				}
				ip, parseErr := netip.ParseAddr(selectedIP)
				if parseErr != nil || !ip.Is4() || !ip.IsGlobalUnicast() {
					w.notice = "Enter the public IPv4 address that you will use in the Web UI."
					break
				}
				cfg.hysteriaCertIP = ip.String()
				w.mu.Unlock()
				return cfg, nil
			}
		case "hysteria-custom":
			switch key.kind {
			case keyUp:
				w.focus = (w.focus + 2) % 3
			case keyDown, keyTab:
				w.focus = (w.focus + 1) % 3
			case keyBackspace:
				w.hysteriaFields[w.focus] = strings.TrimSuffix(w.hysteriaFields[w.focus], lastRune(w.hysteriaFields[w.focus]))
			case keyCharacter:
				if key.char >= 32 && key.char < 127 && len(w.hysteriaFields[w.focus]) < 255 {
					w.hysteriaFields[w.focus] += string(key.char)
				}
			case keyEnter:
				if w.focus < 2 {
					w.focus++
					break
				}
				certPath := resolveHysteriaSource(root, w.hysteriaFields[0], "fullchain.pem")
				keyPath := resolveHysteriaSource(root, w.hysteriaFields[1], "privkey.pem")
				if _, statErr := os.Stat(certPath); statErr != nil {
					w.notice = "Certificate file is missing. Enter its path or copy it to secrets/hysteria."
					w.focus = 0
					break
				}
				if _, statErr := os.Stat(keyPath); statErr != nil {
					w.notice = "Private key file is missing. Enter its path or copy it to secrets/hysteria."
					w.focus = 1
					break
				}
				serverName := strings.TrimSpace(w.hysteriaFields[2])
				if serverName == "" {
					w.notice = "Enter the DNS name or IP address covered by the certificate."
					break
				}
				cfg.hysteriaCertSource = certPath
				cfg.hysteriaKeySource = keyPath
				cfg.hysteriaServerName = serverName
				w.mu.Unlock()
				return cfg, nil
			}
		}
		w.renderLocked()
		w.mu.Unlock()
	}
}

func (w *wizard) ports(ctx context.Context, publicDefault, uiDefault int) (int, int, error) {
	defaults := [2]int{publicDefault, uiDefault}
	for {
		key, err := w.key(ctx)
		if err != nil {
			return 0, 0, err
		}
		w.mu.Lock()
		if (w.width < 64 || w.height < 22) && key.kind != keyEscape {
			w.notice = "Enlarge the terminal before continuing."
			w.renderLocked()
			w.mu.Unlock()
			continue
		}
		switch key.kind {
		case keyEscape:
			w.mu.Unlock()
			return 0, 0, errCancelled
		case keyTab, keyUp, keyDown:
			w.focus = 1 - w.focus
			w.notice = ""
		case keyBackspace:
			w.fields[w.focus] = strings.TrimSuffix(w.fields[w.focus], lastRune(w.fields[w.focus]))
			w.notice = ""
		case keyCharacter:
			if key.char >= '0' && key.char <= '9' && len(w.fields[w.focus]) < 5 {
				w.fields[w.focus] += string(key.char)
				w.notice = ""
			}
		case keyEnter:
			value := w.fields[w.focus]
			if value == "" {
				value = strconv.Itoa(defaults[w.focus])
			}
			port, parseErr := parsePort(value)
			if parseErr != nil {
				w.notice = "Enter a TCP port between 1 and 65535."
				w.fields[w.focus] = ""
				break
			}
			w.fields[w.focus] = strconv.Itoa(port)
			if w.focus == 0 {
				w.focus = 1
				break
			}
			first := w.fields[0]
			if first == "" {
				first = strconv.Itoa(defaults[0])
			}
			publicPort, parseErr := parsePort(first)
			if parseErr != nil {
				w.focus = 0
				w.notice = "Enter a TCP port between 1 and 65535."
				break
			}
			if publicPort == port {
				w.notice = "Choose a different Web UI port; both use the host TCP stack."
				w.fields[1] = ""
				break
			}
			w.renderLocked()
			w.mu.Unlock()
			return publicPort, port, nil
		}
		w.renderLocked()
		w.mu.Unlock()
	}
}

func lastRune(value string) string {
	if value == "" {
		return ""
	}
	_, size := utf8.DecodeLastRuneInString(value)
	return value[len(value)-size:]
}

func (w *wizard) confirm(ctx context.Context) (bool, error) {
	for {
		key, err := w.key(ctx)
		if err != nil {
			return false, err
		}
		w.mu.Lock()
		if (w.width < 64 || w.height < 22) && key.kind != keyEscape {
			w.notice = "Enlarge the terminal before continuing."
			w.renderLocked()
			w.mu.Unlock()
			continue
		}
		switch key.kind {
		case keyEscape:
			w.mu.Unlock()
			return false, nil
		case keyUp, keyDown, keyLeft, keyRight, keyTab:
			w.choice = !w.choice
			w.choiceRaw, w.notice = "", ""
		case keyBackspace:
			w.choiceRaw = strings.TrimSuffix(w.choiceRaw, lastRune(w.choiceRaw))
		case keyCharacter:
			if unicode.IsLetter(rune(key.char)) && len(w.choiceRaw) < 8 {
				w.choiceRaw += string(key.char)
			}
		case keyEnter:
			answer := strings.ToLower(w.choiceRaw)
			switch answer {
			case "", "y", "yes":
				choice := w.choice
				if answer != "" {
					choice = true
				}
				w.mu.Unlock()
				return choice, nil
			case "n", "no":
				w.mu.Unlock()
				return false, nil
			default:
				w.notice = "Enter y or n, or use arrow keys to select an action."
				w.choiceRaw = ""
			}
		}
		w.renderLocked()
		w.mu.Unlock()
	}
}

// Write accepts Docker output while Compose runs and keeps the last lines in
// the viewport. Control bytes are stripped before drawing terminal output.
func (w *wizard) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, b := range data {
		if b == '\n' || b == '\r' {
			if w.partial != "" {
				w.logs = append(w.logs, w.partial)
				w.partial = ""
			}
			continue
		}
		if b >= 32 && b != 127 {
			if len(w.partial) >= maxInstallerLogLine {
				w.partial = w.partial[1:]
			}
			w.partial += string(b)
		}
	}
	if len(w.logs) > 100 {
		w.logs = w.logs[len(w.logs)-100:]
	}
	w.renderLocked()
	return len(data), nil
}

func (w *wizard) logTail(n int) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	lines := append([]string(nil), w.logs...)
	if w.partial != "" {
		lines = append(lines, w.partial)
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	if len(lines) == 0 {
		return ""
	}
	return "\nRecent Docker output:\n  " + strings.Join(lines, "\n  ")
}

type screenLine struct {
	text  string
	style string
}

func (w *wizard) renderLocked() {
	width, height := w.width, w.height
	if width < 1 || height < 1 {
		return
	}
	lines := make([]screenLine, height)
	put := func(row int, text, style string) {
		if row >= 0 && row < height {
			lines[row] = screenLine{text: text, style: style}
		}
	}
	put(0, "  XRAY-EASY  /  PRIVATE SERVER INSTALLER", "header")
	if width < 64 || height < 22 {
		put(height/2, "  Enlarge your terminal to at least 64 × 22 to use the installer.", "accent")
	} else {
		put(2, "  01 CHECK     02 CONFIGURE     03 REVIEW     04 START", "dim")
		put(3, "  "+strings.Repeat("─", width-4), "dim")
		put(5, fmt.Sprintf("  %02d / 04   %s", w.stepNo, w.title), "accent")
		put(6, "  One Xray node · Web UI stays on 127.0.0.1 · persistent keys", "dim")
		panelWidth := min(width-4, 94)
		panelBottom := 17
		if w.stepNo == 4 {
			panelBottom = height - 5
		}
		put(8, "  ╭"+strings.Repeat("─", panelWidth-2)+"╮", "border")
		for row := 9; row < panelBottom; row++ {
			put(row, panelLine("", panelWidth), "border")
		}
		put(panelBottom, "  ╰"+strings.Repeat("─", panelWidth-2)+"╯", "border")
		switch w.stepNo {
		case 1:
			put(10, panelLine("  Checking Docker Engine and Compose", panelWidth), "normal")
			put(12, panelLine("  The installer will use Docker to build and start Xray-easy.", panelWidth), "dim")
		case 2:
			switch w.configPage {
			case "hysteria-choice":
				put(9, panelLine("  Optional Hysteria 2 on the public UDP port", panelWidth), "normal")
				put(11, panelLine("  "+optionText("Off (VLESS only)", w.tlsSelection == 0), panelWidth), fieldStyle(w.tlsSelection == 0))
				put(12, panelLine("  "+optionText("mkcert for public IPv4 (insecure=1)", w.tlsSelection == 1), panelWidth), fieldStyle(w.tlsSelection == 1))
				put(13, panelLine("  "+optionText("My TLS certificate (verified)", w.tlsSelection == 2), panelWidth), fieldStyle(w.tlsSelection == 2))
				put(15, panelLine("  Changing TLS mode reconnects Hysteria 2 clients.", panelWidth), "dim")
			case "hysteria-ip":
				put(10, panelLine("  Public IPv4 for the mkcert certificate", panelWidth), "normal")
				placeholder := "Enter your public IPv4"
				if w.hysteriaSuggestedIP != "" {
					placeholder = w.hysteriaSuggestedIP + " (Enter to use)"
				}
				put(11, panelLine("  "+fieldText(w.hysteriaFields[0], placeholder, true), panelWidth), "selected")
				put(14, panelLine("  Use this same IPv4 as the public host in the Web UI.", panelWidth), "dim")
				put(15, panelLine("  Client TLS verification will be disabled in exported links.", panelWidth), "dim")
			case "hysteria-custom":
				put(9, panelLine("  Full chain PEM (blank: secrets/hysteria/fullchain.pem)", panelWidth), "normal")
				put(10, panelLine("  "+fieldText(w.hysteriaFields[0], "existing file", w.focus == 0), panelWidth), fieldStyle(w.focus == 0))
				put(11, panelLine("  Private key PEM (blank: secrets/hysteria/privkey.pem)", panelWidth), "normal")
				put(12, panelLine("  "+fieldText(w.hysteriaFields[1], "existing file", w.focus == 1), panelWidth), fieldStyle(w.focus == 1))
				put(13, panelLine("  Certificate DNS name or IP address (from SAN)", panelWidth), "normal")
				put(14, panelLine("  "+fieldText(w.hysteriaFields[2], "required", w.focus == 2), panelWidth), fieldStyle(w.focus == 2))
				put(16, panelLine("  A custom certificate keeps TLS verification enabled.", panelWidth), "dim")
			default:
				put(10, panelLine("  Public Xray TCP port", panelWidth), "normal")
				put(11, panelLine("  "+fieldText(w.fields[0], "443", w.focus == 0), panelWidth), fieldStyle(w.focus == 0))
				put(13, panelLine("  Web UI port on VDS loopback", panelWidth), "normal")
				put(14, panelLine("  "+fieldText(w.fields[1], "8080", w.focus == 1), panelWidth), fieldStyle(w.focus == 1))
				put(16, panelLine("  The panel is reached through an SSH tunnel.", panelWidth), "dim")
			}
		case 3:
			put(9, panelLine("  Xray version:       "+w.config.version, panelWidth), "normal")
			put(10, panelLine(fmt.Sprintf("  Public TCP port:    %d", w.config.public), panelWidth), "normal")
			put(11, panelLine(fmt.Sprintf("  Web UI:             127.0.0.1:%d", w.config.ui), panelWidth), "normal")
			put(12, panelLine("  Compose project:    "+w.config.project, panelWidth), "normal")
			hysteriaDescription := "off"
			if w.config.hysteriaEnabled {
				hysteriaDescription = w.config.hysteriaMode
				if w.config.hysteriaMode == "self-signed" {
					hysteriaDescription += " for " + w.config.hysteriaCertIP
				}
			}
			put(13, panelLine("  Hysteria 2 TLS:     "+hysteriaDescription, panelWidth), "normal")
			put(14, panelLine("  "+optionText("Build and start", w.choice), panelWidth), fieldStyle(w.choice))
			put(15, panelLine("  "+optionText("Cancel", !w.choice), panelWidth), fieldStyle(!w.choice))
			if w.choiceRaw != "" {
				put(16, panelLine("  Keyboard answer: "+w.choiceRaw, panelWidth), "dim")
			}
		case 4:
			put(9, panelLine("  Docker Compose output", panelWidth), "normal")
			available := max(0, panelBottom-10)
			logs := append([]string(nil), w.logs...)
			if w.partial != "" {
				logs = append(logs, w.partial)
			}
			if len(logs) > available {
				logs = logs[len(logs)-available:]
			}
			for i, log := range logs {
				put(10+i, panelLine("  "+log, panelWidth), "dim")
			}
			progress := "Waiting for services to become healthy..."
			switch w.title {
			case "Verifying the installation":
				progress = "Running final doctor checks..."
			case "Doctor checks completed":
				progress = "Doctor checks completed."
			case "Doctor checks failed":
				progress = "Doctor found failures; installation is preserved."
			}
			put(height-4, "  "+progress, "accent")
		}
	}
	put(height-3, "  "+strings.Repeat("─", max(0, width-4)), "dim")
	keys := "  ↑↓ / Tab  Move     Enter  Continue     Backspace  Edit     Esc  Cancel     Ctrl+C  Exit"
	if w.stepNo == 4 {
		keys = "  Docker is running. Ctrl+C exits the installer; services remain running."
		if w.title == "Doctor checks failed" {
			keys = "  Services kept running; see doctor details above."
		}
	}
	put(height-2, keys, "dim")
	if w.notice != "" {
		put(height-1, "  "+w.notice, "notice")
	}
	var frame strings.Builder
	for row, line := range lines {
		content := clipRunes(line.text, width)
		if line.style == "header" {
			content += strings.Repeat(" ", max(0, width-utf8.RuneCountInString(content)))
		}
		fmt.Fprintf(&frame, "\x1b[%d;1H\x1b[2K%s%s\x1b[0m", row+1, w.color(line.style), content)
	}
	_, _ = io.WriteString(w.out, frame.String())
}

func panelLine(value string, width int) string {
	inside := max(0, width-2)
	value = clipRunes(value, inside)
	return "  │" + value + strings.Repeat(" ", inside-utf8.RuneCountInString(value)) + "│"
}

func fieldText(value, placeholder string, focused bool) string {
	if value == "" {
		value = placeholder
	}
	marker := "  "
	if focused {
		marker = "› "
	}
	return marker + "[ " + value + " ]"
}

func fieldStyle(focused bool) string {
	if focused {
		return "selected"
	}
	return "normal"
}

func optionText(label string, selected bool) string {
	if selected {
		return "› [ " + label + " ]"
	}
	return "  [ " + label + " ]"
}

func clipRunes(value string, width int) string {
	runes := []rune(value)
	if len(runes) > width {
		return string(runes[:width])
	}
	return value
}

func (w *wizard) color(style string) string {
	if w.noColor {
		return ""
	}
	switch style {
	case "header":
		return "\x1b[1;97;44m"
	case "accent":
		return "\x1b[1;36m"
	case "selected":
		return "\x1b[1;30;46m"
	case "dim", "border":
		return "\x1b[2;37m"
	case "notice":
		return "\x1b[1;33m"
	default:
		return "\x1b[37m"
	}
}
