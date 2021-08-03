package services

import (
	"log"
	"net/http"
)

func RegisterAPIs()  {

	//Api Handlers
	http.HandleFunc("/api/login", Login)
	http.HandleFunc("/api/home", Home)
	http.HandleFunc("/api/refresh", Refresh)

	//Logging and Starting Server
	log.Fatal(http.ListenAndServe(":8080", nil))

}