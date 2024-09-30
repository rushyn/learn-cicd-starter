package auth

import (
	"log"
	"net/http"
	"reflect"
	"testing"
)

func TestValidGetAPIKey(t *testing.T){
	
	req, _ := http.NewRequest("GET", "test.err.local", nil)
	req.Header.Add("Authorization", "ApiKey ThisIsA_TestToken")
	header := req.Header

	funcKey, err := GetAPIKey(header)
	if err !=nil{
		log.Fatal(err)
	}
	actualKey := "ThisIsA_TestToken"
	if !reflect.DeepEqual(funcKey, actualKey){
		t.Fatalf("Expected: %v, got: %v", actualKey, funcKey)
	}

}

func TestNoKeyGetAPIKey(t *testing.T){
	
	req, _ := http.NewRequest("GET", "test.err.local", nil)
	req.Header.Add("Authorization", "")
	header := req.Header

	_, err := GetAPIKey(header)
	if !reflect.DeepEqual(ErrNoAuthHeaderIncluded.Error(), err.Error()){
		t.Fatalf("Expected: %v, got: %v", ErrNoAuthHeaderIncluded.Error(), err.Error())
	}

}


func TestMalformedGetAPIKey(t *testing.T){
	
	req, _ := http.NewRequest("GET", "test.err.local", nil)
	req.Header.Add("Authorization", "ApiKeyThisIsA_TestToken")
	header := req.Header

	_, err := GetAPIKey(header)
	if !reflect.DeepEqual("malformed asuthorization header", err.Error()){
		t.Fatalf("Expected: %v, got: %v", "malformed authorization header", err.Error())
	}

}