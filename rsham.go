// Rsham, a program which spoofs a listening SSH daemon on port 22

package main

import (
	"flag"
	"io/ioutil"
	"net"

	"github.com/inconshreveable/log15"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	var hostKeyFile string
	flag.StringVar(&hostKeyFile, "hostKeyFile", "rsham_id_rsa",
		"key to use as ssh server host key")

	config := LoadServerConfig(hostKeyFile)

	listener, err := net.Listen("tcp", "[::]:22")
	if err != nil {
		log15.Crit("listening on [::]:22", "error", err)
	}
	log15.Info("Listening for connections on [::]:22")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log15.Error("incoming connection rejected", "error", err)
		}

		go sshHandleConnection(conn, config)
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

func sshHandleConnection(nConn net.Conn, config *ssh.ServerConfig) {
	conn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		log15.Warn("incoming connection failed handshake", "error", err)
	}

	log15.Info("Client Connected", "RemoteAddr", nConn.RemoteAddr())

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			log15.Warn("incoming channel rejected", "error", err)
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
					// log15.Info("request payload", "type", req.Type, "payload", req.Payload)
					ok = true

				default:
					log15.Error("request type not implemented!", "type", req.Type)

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
				switch line {
				case "exit":
					term.Write([]byte("Goodbye.\r\n"))
					break read_loop

				case "":

				default:
					log15.Info("Client sent command", "command", line)
					term.Write([]byte("  " + line + "\r\n"))
				}
			}
			channel.Close()
		}()
	}
	log15.Info("Client Disconnected", "RemoteAddr", nConn.RemoteAddr())
}
