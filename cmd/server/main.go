package main

import "github.com/liondadev/paged/server"

func main() {
	svr := server.New()

	svr.Run(":8089")
}
