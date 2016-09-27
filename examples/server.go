package main

import (
	"fmt"
	"net/http"

	"github.com/prashant-agarwala/apiauth"
)

func main() {
	var getAPIKey apiauth.Finder = func(accessID string, request *http.Request) (string, interface{}, error) {

		return "secret_key", "result", nil
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		result, err := apiauth.Authentic(r, getAPIKey)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, "Unauthorized")
			return
		}
		fmt.Fprintf(w, fmt.Sprintf("Authorized: %s", result))
	})
	addr := fmt.Sprintf(":%d", 8080)
	fmt.Println("starting server on ", addr)
	err := http.ListenAndServe(addr, nil)
	if err != nil {
		fmt.Println(err)
	}

}
