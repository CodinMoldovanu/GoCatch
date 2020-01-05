package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"gopkg.in/mcuadros/go-syslog.v2"
)

var errg = godotenv.Load()

var user = os.Getenv("gocatch_user")
var password = os.Getenv("gocatch_password")
var database = os.Getenv("gocatch_db")
var hostname = os.Getenv("gocatch_db_host")

func main() {

	err := godotenv.Load()
	if err != nil {
		log.Fatal("No .env file.")
	}

	channel := make(syslog.LogPartsChannel)
	handler := syslog.NewChannelHandler(channel)

	server := syslog.NewServer()
	server.SetFormat(syslog.Automatic)
	server.SetHandler(handler)
	server.ListenUDP("0.0.0.0:514")
	server.ListenTCP("0.0.0.0:514")
	server.ListenTCP("0.0.0.0:515")
	server.ListenUDP("0.0.0.0:515")

	// fmt.Printf(db)

	db := createConn()
	// fmt.Print(db)
	defer db.Close()
	server.Boot()

	r, _ := regexp.Compile("(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])")

	go func(channel syslog.LogPartsChannel) {
		for logParts := range channel {
			str := logParts["content"]
			origin := r.FindString(fmt.Sprintf("%s", str))

			_, err := db.Exec("INSERT INTO logs(message, timestamp, severity, origin) VALUES ($1, $2, $3, $4)", logParts["content"], logParts["timestamp"], logParts["severity"], origin)
			if err != nil {
				log.Fatal(err)
			}

		}
	}(channel)

	server.Wait()
}

func createConn() *sql.DB {
	connStr := "postgres://" + user + ":" + password + "@" + hostname + "/" + database + "?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		fmt.Print(err.Error())
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
