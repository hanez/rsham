// Rsham, a program which spoofs a listening SSH daemon on port 22

package main

import (
	"flag"
	"io/ioutil"
	"net"
	"os/exec"
	"strings"

	"github.com/inconshreveable/log15"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

var sshLog log15.Logger

func main() {
	var hostKeyFile string
	var bindAddress string
	var listenPort string
	var mode string

	flag.StringVar(&hostKeyFile, "hostKeyFile", "rsham_id_rsa",
		"key to use as ssh server host key")
	flag.StringVar(&bindAddress, "bindAddress", "[::]",
		"address to bind to")
	flag.StringVar(&listenPort, "listenPort", "22",
		"port to listen on")
	flag.StringVar(&mode, "mode", "shell",
		"rsham mode (shell, blocklog, iptablesdrop)")

	flag.Parse()

	sshLog = log15.New()

	fileHandler, err := log15.FileHandler("rsham.log", log15.TerminalFormat())
	if err != nil {
		log15.Crit("can't write to log file", "error", err)
	}
	sshLog.SetHandler(fileHandler)

	config := LoadServerConfig(hostKeyFile)

	listener, err := net.Listen("tcp", bindAddress+":"+listenPort)
	if err != nil {
		log15.Crit("listening on "+bindAddress+":"+listenPort, "error", err)
	}
	log15.Info("Listening for connections on " + bindAddress + ":" + listenPort)

	sshLog.Info("Server Started")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log15.Error("incoming connection rejected", "error", err)
		}

		go sshHandleConnection(mode, conn, config)
	}
}

func LoadServerConfig(hostKeyFile string) *ssh.ServerConfig {
	config := &ssh.ServerConfig{
		KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			// allow them through, we just do this to get their name
			return nil, nil
		},
	}

	privateBytes, err := ioutil.ReadFile(hostKeyFile)
	if err != nil {
		log15.Crit("loading private key", "error", err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log15.Crit("parsing private key", "error", err)
	}

	config.AddHostKey(private)

	return config
}

func sshHandleConnection(mode string, nConn net.Conn, config *ssh.ServerConfig) {
	switch mode {
	case "iptablesdrop":
		ip := nConn.RemoteAddr().String()[:strings.LastIndex(nConn.RemoteAddr().String(), ":")]

		sshLog.Info("adding drop rule to iptables for ip", "ip", ip)
		cmd := exec.Command("iptables", "-I INPUT", "-s "+ip, "-j DROP")
		err := cmd.Run()
		if err != nil {
			sshLog.Error("error blocking IP", "ip", ip, "error", err)
		}

		nConn.Close()

	case "blocklog":
		sshLog.Info("Adding IP to blocklist", "ip", nConn.RemoteAddr())
		blocklist, err := ioutil.ReadFile("blocklist.txt")
		if err != nil {
			log15.Error("reading blocklist", "error", err)
		}

		blocklist = append(blocklist, []byte(nConn.RemoteAddr().String()+"\n")...)

		err = ioutil.WriteFile("blocklist.txt", blocklist, 0644)
		if err != nil {
			log15.Error("writing blocklist", "error", err)
		}

		nConn.Close()

	case "shell":
		conn, chans, reqs, err := ssh.NewServerConn(nConn, config)
		if err != nil {
			sshLog.Warn("incoming connection failed handshake", "error", err)
		}

		if conn != nil {
			sshLog.Info("Client Connected", "User", conn.User(), "RemoteAddr", nConn.RemoteAddr())
		} else {
			sshLog.Info("Client Connected", "RemoteAddr", nConn.RemoteAddr())
		}

		go ssh.DiscardRequests(reqs)

		for newChannel := range chans {
			if newChannel.ChannelType() != "session" {
				newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
				continue
			}
			channel, requests, err := newChannel.Accept()
			if err != nil {
				sshLog.Warn("incoming channel rejected", "error", err)
			}

			go func(in <-chan *ssh.Request) {
				for req := range in {
					ok := false
					switch req.Type {
					case "shell":
						ok = true
						if len(req.Payload) > 0 {
							// We don't accept any
							// commands, only the
							// default shell.
							ok = false
						}

					case "pty-req":
						// sshLog.Info("request payload", "type", req.Type, "payload", req.Payload)
						ok = true

					default:
						if conn != nil {
							sshLog.Error("request type not implemented!", "user", conn.User(), "RemoteAddr", nConn.RemoteAddr(), "type", req.Type)
						} else {
							sshLog.Error("request type not implemented!", "RemoteAddr", nConn.RemoteAddr(), "type", req.Type)
						}

					}
					req.Reply(ok, nil)
				}
			}(requests)

			term := terminal.NewTerminal(channel, "> ")
			term.Write([]byte("Hi " + conn.User() + ".\r\nType 'exit' or press Ctrl+D to leave.\r\n"))

			go func() {
			read_loop:
				for {
					line, err := term.ReadLine()
					if err != nil {
						break read_loop
					}
					sshLog.Info("Client sent command", "user", conn.User(), "RemoteAddr", nConn.RemoteAddr(), "command", line)
					switch line {
					case "exit":
						term.Write([]byte("Goodbye.\r\n"))
						break read_loop

					case "", "help":
						term.Write([]byte("Commands:\r\n  exit\r\n  help\r\n  bell\r\n"))

					case "bell":
						for {
							term.Write([]byte{0x07})
						}

					default:
						term.Write([]byte("  " + line + "\r\n"))
					}
				}
				channel.Close()
			}()
		}
		if conn != nil {
			sshLog.Info("Client Disconnected", "User", conn.User(), "RemoteAddr", nConn.RemoteAddr())
		} else {
			sshLog.Info("Client Disconnected", "RemoteAddr", nConn.RemoteAddr())
		}

	default:
		log15.Crit("invalid rsham mode specified!", "mode", mode)
	}
}
