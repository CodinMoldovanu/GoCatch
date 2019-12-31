package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"gopkg.in/mcuadros/go-syslog.v2"
)

var user = os.Getenv("gocatch_user")
var password = os.Getenv("gocatch_password")
var database = os.Getenv("gocatch_db")
var hostname = os.Getenv("gocatch_db_host")

func main() {
	channel := make(syslog.LogPartsChannel)
	handler := syslog.NewChannelHandler(channel)

	server := syslog.NewServer()
	server.SetFormat(syslog.Automatic)
	server.SetHandler(handler)
	server.ListenUDP("0.0.0.0:514")
	server.ListenTCP("0.0.0.0:514")
	server.ListenTCP("0.0.0.0:515")
	server.ListenUDP("0.0.0.0:515")

	db := createConn()
	server.Boot()

	go func(channel syslog.LogPartsChannel) {
		fmt.Println("Inside goRoutine")
		fmt.Println(len(channel))
		for logParts := range channel {
			fmt.Print(logParts["content"])
			origin := strings.Split(fmt.Sprintf("%v", logParts["content"]), " ")
			if isIP(origin[6]) {
				_, err := db.Exec("INSERT INTO logs(message, time, severity, origin) VALUES ($1, $2, $3, $4)", logParts["content"], logParts["timestamp"], logParts["severity"])
				if err != nil {
					log.Fatal(err)
				}
			} else {
				for i := range origin {
					if isIP(origin[i]) {
						_, err := db.Exec("INSERT INTO logs(message, timestamp, severity, origin) VALUES ($1, $2, $3, $4)", logParts["content"], logParts["timestamp"], logParts["severity"])
						if err != nil {
							log.Fatal(err)
						}
						break
					}
				}
			}

		}
	}(channel)

	server.Wait()
}

func createConn() *sql.DB {
	connStr := "postgres://" + user + ":" + password + "@" + hostname + "/" + database + "?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	// defer db.Close()
	return db
}

func isIP(ip string) bool {
	ipBlockCount := strings.Split(ip, ".")

	if len(ipBlockCount) != 4 {
		return false
	}

	for _, x := range ipBlockCount {
		if i, err := strconv.Atoi(x); err == nil {
			if i > 0 || i < 255 {
				return true
			} else {
				return false
			}
		}
	}

	return false
}
