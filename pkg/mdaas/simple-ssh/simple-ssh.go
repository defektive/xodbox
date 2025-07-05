package main

import (
	"fmt"
	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
	"io"
	"log"
	"os"
	"os/exec"
)

func setWinsize(f *os.File, w, h int) {
	//syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
	//	uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0})))
}

func main() {
	ssh.Handle(func(s ssh.Session) {
		cmd := exec.Command("/bin/bash")
		ptyReq, winCh, isPty := s.Pty()
		if isPty {
			cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
			f, err := pty.Start(cmd)
			if err != nil {
				panic(err)
			}
			go func() {
				for win := range winCh {
					setWinsize(f, win.Width, win.Height)
				}
			}()
			go func() {
				i, err := io.Copy(f, s) // stdin
				log.Printf("wrote %d bytes, have err: %v", i, err)
			}()
			i, err := io.Copy(s, f) // stdout
			log.Printf("wrote %d bytes, have err: %v", i, err)
			err = cmd.Wait()
			if err != nil {
				log.Printf("Command finished with error: %v", err)
			}
		} else {
			i, err := io.WriteString(s, "No PTY requested.\n")
			log.Printf("no pty: wrote %d, has err: %v", i, err)
			s.Exit(1)
		}
	})

	log.Println("starting ssh server on port 2222...")
	log.Fatal(ssh.ListenAndServe(":2222", nil))
}
