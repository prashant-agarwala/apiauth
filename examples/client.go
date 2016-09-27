package main

import (
	"bytes"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/prashant-agarwala/apiauth"
)

func postCall() error {
	posturl := "http://localhost:8070/api/v1/lists/create.json"
	var jsonStr = []byte(`{"currency":"INR","amount":"1"}`)
	req, err := http.NewRequest("POST", posturl, bytes.NewBuffer(jsonStr))
	clientid := "myclientid"
	secret := "mysecretkey"

	err = apiauth.Sign(req, clientid, secret)
	if err != nil {
		return err
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	log.Println("response Body:", string(body))
	return nil
}

func getCall() error {
	geturl := "http://localhost:8070/api/v1/lists.json"
	req, err := http.NewRequest("GET", geturl, nil)
	clientid := "myclientid"
	secret := "mysecretkey"

	err = apiauth.Sign(req, clientid, secret)
	if err != nil {
		return err
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	log.Println("response Body:", string(body))
	return nil
}

//
// func main() {
// 	if err := getCall(); err != nil {
// 		log.Fatal(err)
// 	}
// 	if err := postCall(); err != nil {
// 		log.Fatal(err)
// 	}
// }
