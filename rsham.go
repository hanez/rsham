// Rsham, a program which spoofs a listening SSH daemon on port 22

package main

import (
	"encoding/base64"
	"io/ioutil"
	"net"

	"github.com/inconshreveable/log15"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

var usernames *UsernameDirectory

func main() {
	usernames = NewUsernameDirectory()

	sshConfig := &ssh.ServerConfig{
		NoClientAuth: true,
		KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			// allow them through, we just do this to get their name
			return nil, nil
		},
		AuthLogCallback: func(conn ssh.ConnMetadata, method string, err error) {
			// store the username against the connection session id
			usernames.StoreUsername(conn.SessionID(), conn.User())
		},
	}

	privateBytes, err := ioutil.ReadFile("rsham_id_rsa")
	if err != nil {
		log15.Crit("loading private key", "error", err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log15.Crit("parsing private key", "error", err)
	}

	sshConfig.AddHostKey(private)

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

		go sshHandleConnection(conn, sshConfig)
	}
}

func sshHandleConnection(nConn net.Conn, config *ssh.ServerConfig) {
	log15.Info("Client Connected", "RemoteAddr", nConn.RemoteAddr())
	conn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		log15.Warn("incoming connection failed handshake", "error", err)
	}

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
		term.Write([]byte("Hi " + usernames.GetUsername(conn.SessionID()) + ".\r\nType 'exit' or press Ctrl+D to leave.\r\n"))

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
					term.Write([]byte("  " + line + "\r\n"))
				}
			}
			channel.Close()
		}()
	}
	log15.Info("Client Disconnected", "RemoteAddr", nConn.RemoteAddr())
}

type UsernameDirectory struct {
	users map[string]string
}

func NewUsernameDirectory() *UsernameDirectory {
	return &UsernameDirectory{users: make(map[string]string)}
}

func (u *UsernameDirectory) StoreUsername(sessionID []byte, name string) {
	u.users[base64.StdEncoding.EncodeToString(sessionID)] = name
}

func (u *UsernameDirectory) GetUsername(sessionID []byte) string {
	if name, ok := u.users[base64.StdEncoding.EncodeToString(sessionID)]; ok {
		return name
	}
	return "[user]"
}
