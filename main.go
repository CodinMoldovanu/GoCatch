package main

import (
	"fmt"

	"gopkg.in/mcuadros/go-syslog.v2"
)

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

	server.Boot()

	go func(channel syslog.LogPartsChannel) {
		fmt.Println("Inside goRoutine")
		fmt.Println(len(channel))
		for logParts := range channel {
			fmt.Println(logParts)
			fmt.Print(logParts["content"])
		}
	}(channel)

	server.Wait()
}
