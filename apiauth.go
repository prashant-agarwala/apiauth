package apiauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

//Finder is a method which takes clients accessID and the request as input and
// returns secretKey of the associated accessID.
// It also allows you to return any additional result you might want to return
// from Authentic method
type Finder func(accessID string, req *http.Request) (secretKey string, result interface{}, err error)

var errorMD5 = errors.New("MD5 mismatch occurred")
var errorSignMismatch = errors.New("Signature Mismatch occurred")
var errorReqOld = errors.New("Request too old")
var errorAuthHeader = errors.New("Malformed Auth Header")
var gmt *time.Location

func init() {
	loc, err := time.LoadLocation("Etc/GMT")
	if err != nil {
		log.Panic("apiauth: Can not load timezone Etc/GMT: ", err)
	}
	gmt = loc
}

//relaxation for out of sync servers
const maxTimeOffset time.Duration = 30 * time.Second

//Authentic Determines if the request is authentic given the request and a finder method
//and returns the result returned by Finder if request is authentic else error
func Authentic(request *http.Request, f Finder) (interface{}, error) {
	if requestTooOld(request) {
		return nil, errorReqOld
	}
	accessID, hmacHash, err := parseAuthHeader(request)
	if err != nil {
		return nil, err
	}
	if err = validateMD5(request); err != nil {
		return nil, err
	}
	secretKey, finderInfo, err := f(accessID, request)
	if err != nil {
		return nil, err
	}
	if signRequest(request, secretKey) != hmacHash {
		return nil, errorSignMismatch
	}
	return finderInfo, nil
}

//Sign signs an HTTP request using the client's access id and secret key
//and modifies request object by adding some headers.
func Sign(request *http.Request, accessID, secretKey string) error {
	err := setMD5(request)
	if err != nil {
		return err
	}
	setDate(request)
	setAuthorizationHeader(request, accessID, secretKey)
	return nil
}

func requestTooOld(request *http.Request) bool {
	headerTime, err := time.Parse(time.RFC1123, getDate(request))
	if err != nil {
		return true
	}
	diff := time.Since(headerTime)
	if diff < -maxTimeOffset || diff > (900*time.Second+maxTimeOffset) {
		return true
	}
	return false
}

func signRequest(request *http.Request, secretKey string) string {
	hash := hmac.New(sha1.New, []byte(secretKey))
	hash.Write([]byte(evaluateCanonicalString(request)))
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
}

func parseAuthHeader(request *http.Request) (string, string, error) {
	authHeader := request.Header.Get("Authorization")
	if authHeader == "" {
		return "", "", errorAuthHeader
	}
	authSpaceSplit := strings.Split(authHeader, " ")
	if len(authSpaceSplit) != 2 {
		return "", "", errorAuthHeader
	}
	authColonSplit := strings.Split(authSpaceSplit[1], ":")
	if len(authColonSplit) != 2 {
		return "", "", errorAuthHeader
	}
	return authColonSplit[0], authColonSplit[1], nil
}

func evaluateCanonicalString(request *http.Request) string {
	var buffer bytes.Buffer
	buffer.WriteString(request.Method)
	buffer.WriteString(",")
	buffer.WriteString(getContentType(request))
	buffer.WriteString(",")
	buffer.WriteString(getMD5(request))
	buffer.WriteString(",")
	buffer.WriteString(getPath(request))
	buffer.WriteString(",")
	buffer.WriteString(getDate(request))
	canStr := buffer.String()
	return canStr
}

func getContentType(request *http.Request) string {
	return request.Header.Get("Content-Type")
}

func getDate(request *http.Request) string {
	return request.Header.Get("Date")
}

func getPath(request *http.Request) string {
	return request.URL.RequestURI()
}

func getMD5(request *http.Request) string {
	return request.Header.Get("Content-Md5")
}

func evaluateMD5Hash(request *http.Request) (string, error) {
	if request.Method == "POST" || request.Method == "PUT" {
		bodyBytes, err := ioutil.ReadAll(request.Body)
		if err != nil {
			return "", err
		}
		// Restore the io.ReadCloser to its original state
		request.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
		ctMd5 := md5.New()
		ctMd5.Write(bodyBytes)
		return base64.StdEncoding.EncodeToString(ctMd5.Sum(nil)), nil
	}
	return "", nil
}

func validateMD5(request *http.Request) error {
	expectedHash, err := evaluateMD5Hash(request)
	if err != nil {
		return err
	}
	if expectedHash != getMD5(request) {
		return errorMD5
	}
	return nil
}

func setDate(request *http.Request) {
	request.Header.Add("Date", time.Now().In(gmt).Format(time.RFC1123))
}

func setMD5(request *http.Request) error {
	calculatedMD5, err := evaluateMD5Hash(request)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Md5", calculatedMD5)
	return nil
}

func setAuthorizationHeader(request *http.Request, accessID, secretKey string) {
	request.Header.Add("Authorization", fmt.Sprintf("APIAuth %s:%s", accessID, signRequest(request, secretKey)))
}
