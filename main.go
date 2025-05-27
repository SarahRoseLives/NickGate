package main

import (
        "flag"
        "io"
        "log"
        "net"
        "os"
        "os/exec"
        "os/signal"
        "path/filepath"
        "syscall"
        "unsafe"

        "nickgate/config"
        "nickgate/nickserv"

        "github.com/creack/pty"
        "golang.org/x/crypto/ssh"
)

// Server represents the SSH server
type Server struct {
        config      *ssh.ServerConfig
        nsAuth      *nickserv.AuthClient
        sshPort     string
        hostKeyFile string
        forceCmd    string
}

// NewServer creates a new SSH server instance
func NewServer(cfg *config.Config) (*Server, error) {
        server := &Server{
                sshPort:     cfg.SSHPort,
                hostKeyFile: cfg.HostKeyFile,
                forceCmd:    cfg.ForceCommand,
                nsAuth: nickserv.NewAuthClient(
                        cfg.NickServAPI.URL,
                        cfg.NickServAPI.Token,
                ),
        }

        sshConfig := &ssh.ServerConfig{
                PasswordCallback: server.passwordCallback,
        }

        hostKeyBytes, err := os.ReadFile(server.hostKeyFile)
        if err != nil {
                return nil, err
        }
        hostKey, err := ssh.ParsePrivateKey(hostKeyBytes)
        if err != nil {
                return nil, err
        }
        sshConfig.AddHostKey(hostKey)

        server.config = sshConfig
        return server, nil
}

// passwordCallback authenticates users against NickServ
func (s *Server) passwordCallback(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
        ok, err := s.nsAuth.Authenticate(conn.User(), string(password))
        if err != nil {
                log.Printf("NickServ auth error for %s: %v", conn.User(), err)
                return nil, err
        }
        if !ok {
                return nil, ssh.ErrNoAuth
        }
        return &ssh.Permissions{
                Extensions: map[string]string{
                        "user":        conn.User(),
                        "remote-addr": conn.RemoteAddr().String(),
                        "password":    string(password), // Store the password in permissions
                },
        }, nil
}

// handleSession handles an SSH session channel
func (s *Server) handleSession(newChannel ssh.NewChannel, permissions *ssh.Permissions) {
        channel, requests, err := newChannel.Accept()
        if err != nil {
                log.Printf("Could not accept channel: %v", err)
                return
        }
        defer channel.Close()

        user := permissions.Extensions["user"]
        remoteAddr := permissions.Extensions["remote-addr"]
        password := permissions.Extensions["password"] // Retrieve the password from permissions

        cmd := exec.Command(s.forceCmd)
        cmd.Env = append(os.Environ(),
                "SSH_USER="+user,
                "SSH_CLIENT="+remoteAddr,
                "NICK="+user,
                "PASS="+password, // Set the PASS environment variable here
                "TERM=xterm-256color",
                "LANG=en_US.UTF-8",
        )

        // Allocate a PTY for the command
        ptmx, err := pty.Start(cmd)
        if err != nil {
                log.Printf("Failed to start command with PTY: %v", err)
                channel.Close()
                return
        }
        defer ptmx.Close()

        sigch := make(chan os.Signal, 1)
        signal.Notify(sigch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
        go func() {
                for sig := range sigch {
                        if cmd.Process != nil {
                                cmd.Process.Signal(sig)
                        }
                }
        }()

        // Handle channel requests
        go func() {
                for req := range requests {
                        switch req.Type {
                        case "pty-req":
                                termLen := req.Payload[3]
                                w, h := parseDims(req.Payload[termLen+4:])
                                SetWinsize(ptmx.Fd(), w, h)
                                req.Reply(true, nil)
                        case "window-change":
                                w, h := parseDims(req.Payload)
                                SetWinsize(ptmx.Fd(), w, h)
                                req.Reply(true, nil)
                        case "shell":
                                // The client's "shell" request just implies they want an interactive session.
                                // Since we're providing one via the force_command, we reply true.
                                // This prevents the "shell request failed" error.
                                log.Printf("Client requested shell. Force command already running. Allowing for user %s.", user)
                                req.Reply(true, nil)
                        case "exec":
                                // If the client sends an 'exec' request, it's either redundant or an attempt
                                // to run something else. Given our "force_command" design, we *still* only run
                                // what we defined. We reply true to avoid the error and keep the channel open.
                                // The actual command passed in `req.Payload` is ignored.
                                log.Printf("Client requested 'exec' command. Force command already running. Allowing for user %s.", user)
                                req.Reply(true, nil)
                        default:
                                if req.WantReply {
                                        log.Printf("Unsupported SSH channel request type '%s' from user %s. Rejecting.", req.Type, user)
                                        req.Reply(false, nil)
                                }
                        }
                }
        }()

        // Copy stdin/stdout between the SSH channel and the PTY
        go func() {
                io.Copy(channel, ptmx) // pty stdout to ssh channel
        }()
        go func() {
                io.Copy(ptmx, channel) // ssh channel stdin to pty
        }()

        // Wait for the command to exit
        err = cmd.Wait()
        if err != nil {
                log.Printf("Force command finished with error for user %s: %v", user, err)
        } else {
                log.Printf("Force command finished successfully for user %s.", user)
        }

        signal.Stop(sigch)
        close(sigch)
        channel.Close()
        ptmx.Close()
}

// parseDims extracts terminal dimensions (width, height) from the payload
func parseDims(b []byte) (width, height uint32) {
        width = uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
        height = uint32(b[4])<<24 | uint32(b[5])<<16 | uint32(b[6])<<8 | uint32(b[7])
        return
}

// winsize stores the window size information
type winsize struct {
        ws_row    uint16
        ws_col    uint16
        ws_xpixel uint16
        ws_ypixel uint16
}

// SetWinsize sets the size of the given pty
func SetWinsize(fd uintptr, w, h uint32) {
        ws := &winsize{ws_col: uint16(w), ws_row: uint16(h)}
        _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCSWINSZ, uintptr(unsafe.Pointer(ws)))
        if errno != 0 {
                log.Printf("SetWinsize failed: %v", errno)
        }
}

// Start initiates the SSH server listener
func (s *Server) Start() error {
        listener, err := net.Listen("tcp", ":"+s.sshPort)
        if err != nil {
                return err
        }
        defer listener.Close()

        log.Printf("NickGate SSH server started on port %s (forcecommand=%s)", s.sshPort, s.forceCmd)

        for {
                conn, err := listener.Accept()
                if err != nil {
                        log.Printf("Connection accept error: %v", err)
                        continue
                }
                go s.handleConnection(conn)
        }
}

// handleConnection handles an incoming SSH connection
func (s *Server) handleConnection(conn net.Conn) {
        defer conn.Close()
        sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.config)
        if err != nil {
                log.Printf("SSH handshake failed from %s: %v", conn.RemoteAddr(), err)
                return
        }
        defer sshConn.Close()

        log.Printf("New SSH connection: user=%s client=%s version=%s",
                sshConn.User(),
                sshConn.RemoteAddr(),
                sshConn.ClientVersion())

        go ssh.DiscardRequests(reqs)

        for newChannel := range chans {
                if newChannel.ChannelType() != "session" {
                        newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
                        continue
                }
                go s.handleSession(newChannel, sshConn.Permissions)
        }
}

func main() {
        var configPath string
        flag.StringVar(&configPath, "config", "", "Path to configuration file")
        flag.Parse()

        if configPath == "" {
                exePath, err := os.Executable()
                if err != nil {
                        log.Fatalf("Failed to get executable path: %v", err)
                }
                configPath = filepath.Join(filepath.Dir(exePath), "nickgate.conf")
        }

        cfg, err := config.Load(configPath)
        if err != nil {
                log.Fatalf("Config load error: %v", err)
        }

        server, err := NewServer(cfg)
        if err != nil {
                log.Fatalf("Server init failed: %v", err)
        }

        if err := server.Start(); err != nil {
                log.Fatalf("Server crashed: %v", err)
        }
}
