package utils

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

func HttpPost(url string, headers map[string]string, data string) (string, error) {

	client := &http.Client{}

	req, err := http.NewRequest("POST", url, strings.NewReader(data))
	if err != nil {
		// handle error
		log.Println(err)
		return "", err
	}

	for key := range headers {
		fmt.Println(key, ":", headers[key])
		req.Header.Set(key, headers[key])
	}

	resp, err := client.Do(req)

	defer resp.Body.Close()

	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		// handle error
		log.Println(err)
		return "", err

	}

	//fmt.Println(string(body))
	//log.Printf(string(body))
	return string(body), nil
	//jsonStr := string(body)
	//fmt.Println("jsonStr", jsonStr)
}

func HttpsPost(url string, headers map[string]string, data string) (string, error) {

	//client := &http.Client{}
	// tr := &http.Transport{
	// 	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	// }
	pool := x509.NewCertPool()
	caCertPath := "UP.pem"

	caCrt, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		fmt.Println("ReadFile err:", err)
		//return
	}

	pool.AppendCertsFromPEM(caCrt)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:            pool,
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("POST", url, strings.NewReader(data))
	if err != nil {
		// handle error
		log.Println(err)
		return "", err
	}

	for key := range headers {
		fmt.Println(key, ":", headers[key])
		req.Header.Set(key, headers[key])
	}

	resp, err := client.Do(req)

	defer resp.Body.Close()

	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		// handle error
		log.Println(err)
		return "", err

	}

	//fmt.Println(string(body))
	//log.Printf(string(body))
	return string(body), nil
	//jsonStr := string(body)
	//fmt.Println("jsonStr", jsonStr)
}

func HttpsPostx(url string, headers map[string]string, data []byte) ([]byte, error) {

	//client := &http.Client{}
	// tr := &http.Transport{
	// 	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	// }
	pool := x509.NewCertPool()
	caCertPath := "UP.pem"

	caCrt, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		fmt.Println("ReadFile err:", err)
		//return
	}

	pool.AppendCertsFromPEM(caCrt)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:            pool,
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{Transport: tr}
	log.Println("begin post...")
	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		// handle error
		log.Println("error..")
		log.Println(err)
		return nil, err
	}

	for key := range headers {
		fmt.Println(key, ":", headers[key])
		req.Header.Set(key, headers[key])
	}

	resp, err := client.Do(req)
	if err != nil {
		// handle error
		log.Println("error1..")
		log.Println(err)
		return nil, err
	}

	defer resp.Body.Close()

	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		// handle error
		log.Println(err)
		return nil, err

	}

	//fmt.Println(string(body))
	//log.Printf(string(body))
	return body, nil
	//jsonStr := string(body)
	//fmt.Println("jsonStr", jsonStr)
}

func UpHttpsPost(url string, body []byte) ([]byte, error) {
	headers := make(map[string]string)
	headers["User-Agent"] = "Donjin Http 0.1"
	headers["Content-Type"] = " x-ISO-TPDU/x-auth"
	headers["Cache-Control"] = "no-cache"
	out, err := HttpsPostx(url, headers, body)
	if err != nil {
		//log.Info(sn + err)
		return nil, err
	}
	//log.Info(strout)
	return out, nil
}
