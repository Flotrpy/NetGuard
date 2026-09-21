// Deliberately vulnerable Go (test fixture, never deploy).
package main

import (
	"crypto/md5"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

func handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", r.FormValue("id"))) // SQL injection
	exec.Command("sh", "-c", r.FormValue("cmd")).Run()                             // command injection
	_ = md5.New()                                                                  // weak hash
	_ = &tls.Config{InsecureSkipVerify: true}                                      // TLS off
}
