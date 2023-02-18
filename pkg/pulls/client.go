package pulls

import (
	"encoding/json"
	"io"
	"log"
	"math"
	"time"

	"github.com/cli/go-gh/pkg/api"
)

type Pull struct {
	Mergeable bool
	State     string
}

type Merge struct {
	Merged  bool
	Message string
}

func GetPullRequest(client api.RESTClient, owner, name, prNumber string, pull *Pull) {
	err := client.Get("repos/"+owner+"/"+name+"/pulls/"+prNumber, pull)
	if err != nil {
		log.Fatal(err)
	}
}

func WaitForMergable(client api.RESTClient, owner, name, prNumber string) bool {
	pull := Pull{}

	for i := 0; i < 4; i++ {
		time.Sleep(5 * (time.Duration)(math.Pow(2, (float64)(i))) * time.Second)
		GetPullRequest(client, owner, name, prNumber, &pull)
		if pull.Mergeable {
			return true
		}
	}

	return false
}

func MergePullRequest(client api.RESTClient, owner, name, prNumber string, merge *Merge) {
	urlPathStr := "repos/" + owner + "/" + name + "/pulls/" + prNumber + "/merge"
	urlPath := &urlPathStr

	resp, err := client.Request("PUT", *urlPath, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	err = json.Unmarshal(body, merge)
	if err != nil {
		log.Fatal(err)
	}
}
