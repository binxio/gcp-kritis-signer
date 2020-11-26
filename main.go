/*
Copyright 2020 binx.io B.V.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	ca "cloud.google.com/go/containeranalysis/apiv1beta1"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/discovery"
	grafeaspb "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/grafeas"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/docker/distribution/reference"
	"github.com/golang/glog"
	"github.com/grafeas/kritis/pkg/attestlib"
	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/crd/vulnzsigningpolicy"
	"github.com/grafeas/kritis/pkg/kritis/metadata/containeranalysis"
	"github.com/grafeas/kritis/pkg/kritis/signer"
	"github.com/grafeas/kritis/pkg/kritis/util"
	"k8s.io/apimachinery/pkg/util/yaml"
)

var (
	attestationProject string
	overwrite          bool
	noteName           string
	kmsKeyName         string
	digestAlgorithm    string
	policyPath         string
	policyDocument     string
	policy             *v1beta1.VulnzSigningPolicy
	client             *containeranalysis.Client
	grafeas            *ca.GrafeasV1Beta1Client
	kmsSigner          attestlib.Signer
)

type EvaluationStatus string

const (
	Ok        EvaluationStatus = "ok"
	Signed    EvaluationStatus = "signed"
	NotSigned EvaluationStatus = "not-signed"
	Failed    EvaluationStatus = "failed"
)

type SignRequest struct {
	Image string
}

type SignResponse struct {
	Image      string           `json:"image,omitempty"`
	Status     EvaluationStatus `json:"status,omitempty"`
	Message    string           `json:"message,omitempty"`
	Violations []string         `json:"violations,omitempty"`
}

func WriteResponse(w http.ResponseWriter, response SignResponse, code int) {
	body, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	glog.Infof("%s\t%s", response.Image, response.Message)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	w.Write(body)
}

type PubSubMessage struct {
	Message struct {
		Data []byte `json:"data,omitempty"`
		ID   string `json:"id"`
	} `json:"message"`
	Subscription string `json:"subscription"`
}

type ContainerAnalysisOccurrenceEvent struct {
	Name             string    `json:"name"`
	Kind             string    `json:"kind"`
	NotificationTime time.Time `json:"notificationTime"`
}

func GetOccurrence(event ContainerAnalysisOccurrenceEvent) (*grafeaspb.Occurrence, error) {
	request := grafeaspb.GetOccurrenceRequest{Name: event.Name}
	response, err := grafeas.GetOccurrence(context.Background(), &request)
	if err != nil {
		return nil, fmt.Errorf("could not retrieve discovery occurrence %s", event.Name)
	}
	return response, nil
}

func containerAnalysisEvent(w http.ResponseWriter, r *http.Request) {
	var m PubSubMessage
	var event ContainerAnalysisOccurrenceEvent
	err := json.NewDecoder(r.Body).Decode(&m)
	if err != nil {
		http.Error(w, "could not unmarshal the pubsub message", http.StatusBadRequest)
		return
	}

	err = json.Unmarshal(m.Message.Data, &event)
	if err != nil {
		http.Error(w, "could not unmarshal container analysis occurrence event from pubsub message", http.StatusBadRequest)
		return
	}

	if event.Kind != "DISCOVERY" {
		http.Error(w, "ignoring non-DISCOVERY occurrence", http.StatusOK)
		return
	}

	occurrence, err := GetOccurrence(event)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	status := occurrence.GetDiscovered().GetDiscovered().GetAnalysisStatus()
	if status != discovery.Discovered_FINISHED_SUCCESS {
		http.Error(w, fmt.Sprintf("ignoring DISCOVERY occurrence in status %s", string(status)), http.StatusOK)
		return
	}
	image := occurrence.Resource.Uri
	if strings.HasPrefix(image, "https://") {
		image = image[8:]
	}
	request := SignRequest{Image: image}
	doCheckAndSign(w, request, http.StatusOK)
}

func DoCheck(image string) ([]string, error) {
	var result []string
	ref, err := reference.ParseAnyReference(image)
	if err != nil {
		return nil, fmt.Errorf("failed to parse container image reference %s, %s", image, err)
	}

	if _, ok := ref.(reference.Digested); !ok {
		return nil, fmt.Errorf("image reference should have digest")
	}

	vulnerabilities, err := client.Vulnerabilities(image)
	if err != nil {
		return nil, fmt.Errorf("failed to read discovered vulnerabilities. %s", err)
	}

	if vulnerabilities == nil {
		return nil, fmt.Errorf("no vulnerabilities found")
	}

	violations, err := vulnzsigningpolicy.ValidateVulnzSigningPolicy(*policy, image, vulnerabilities)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate image against policy %s, %s", policy.Name, err)
	}

	if violations != nil && len(violations) != 0 {
		result = make([]string, len(violations))
		for i, v := range violations {
			result[i] = string(v.Reason())
		}
	}
	return result, nil
}

func DoSign(image string) error {
	project := attestationProject
	if project == "" {
		project = util.GetProjectFromContainerImage(image)
	}

	noteSigner := signer.New(client, kmsSigner, noteName, project, overwrite)
	return noteSigner.SignImage(image)
}

func check(w http.ResponseWriter, r *http.Request) {
	var request SignRequest
	var response SignResponse

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		response.Status = Failed
		response.Message = fmt.Sprintf("failed to decode body, %s", err)
		WriteResponse(w, response, http.StatusBadRequest)
		return
	}
	response.Image = request.Image

	violations, err := DoCheck(request.Image)
	if err != nil {
		response.Status = Failed
		response.Message = err.Error()
		WriteResponse(w, response, http.StatusBadRequest)
		return
	}
	if violations != nil {
		response.Status = Failed
		response.Violations = violations
		WriteResponse(w, response, http.StatusUnprocessableEntity)
	} else {
		response.Status = Ok
		WriteResponse(w, response, http.StatusOK)
	}
}

func doCheckAndSign(w http.ResponseWriter, request SignRequest, violationStatus int) {
	response := SignResponse{Image: request.Image}

	violations, err := DoCheck(request.Image)
	if err != nil {
		response.Status = Failed
		response.Message = err.Error()
		WriteResponse(w, response, http.StatusBadRequest)
		return
	}

	if violations != nil {
		response.Status = NotSigned
		response.Message = fmt.Sprintf("image violates policy")
		response.Violations = violations
		WriteResponse(w, response, violationStatus)
		return
	}

	err = DoSign(request.Image)
	if err != nil {
		response.Status = Failed
		response.Message = err.Error()
		WriteResponse(w, response, http.StatusInternalServerError)
		return
	}

	response.Status = Signed
	WriteResponse(w, response, http.StatusOK)
}

func checkAndSign(w http.ResponseWriter, r *http.Request) {

	var request SignRequest
	var response SignResponse

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		response.Status = Failed
		response.Message = fmt.Sprintf("failed to decode body, %s", err)
		WriteResponse(w, response, http.StatusBadRequest)
		return
	}
	doCheckAndSign(w, request, http.StatusUnprocessableEntity)
}

func ParsePolicy(policyDocument string) (*v1beta1.VulnzSigningPolicy, error) {
	policy := v1beta1.VulnzSigningPolicy{}
	if err := yaml.NewYAMLToJSONDecoder(strings.NewReader(policyDocument)).Decode(&policy); err != nil {
		return nil, fmt.Errorf("failed to parse policy, %s", err)
	}
	return &policy, nil
}

func ReadPolicyFile(path string) (*v1beta1.VulnzSigningPolicy, error) {
	policy := v1beta1.VulnzSigningPolicy{}
	policyFile, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load policy file '%s', %s", path, err)
	}
	defer policyFile.Close()
	if err := yaml.NewYAMLToJSONDecoder(policyFile).Decode(&policy); err != nil {
		return nil, fmt.Errorf("failed to parse policy from '%s', %s", path, err)
	}

	return &policy, nil
}

func isFlagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func main() {
	var err error
	flag.StringVar(&policyPath, "policy-path", "", "path to vulnerability signing policy")
	flag.StringVar(&policyDocument, "policy", "", "literal policy document")
	flag.StringVar(&noteName, "note-name", "", "to create attestations.")
	flag.StringVar(&attestationProject, "project", "", "project to store attestations in")
	flag.BoolVar(&overwrite, "overwrite", false, "overwrite existing attestation")
	flag.StringVar(&kmsKeyName, "kms-key", "", "kms key name to sign with.")
	flag.StringVar(&digestAlgorithm, "digest-algorithm", "", "specified for the kms key")
	flag.Parse()

	if policyPath == "" {
		policyPath = os.Getenv("ATTESTATION_POLICY_PATH")
	}

	if policyDocument == "" {
		policyDocument = os.Getenv("ATTESTATION_POLICY")
	}

	if policyPath != "" && policyDocument != "" {
		glog.Fatalf("either set the policy path or the policy document, not both")
	}

	if policyPath == "" && policyDocument == "" {
		glog.Fatalf("no policy path or document is specified")
	}

	if policyPath != "" {
		policy, err = ReadPolicyFile(policyPath)
		if err != nil {
			glog.Fatal(err)
		}
	} else {
		policy, err = ParsePolicy(policyDocument)
		if err != nil {
			glog.Fatal(err)
		}
	}

	if noteName == "" {
		noteName = os.Getenv("ATTESTATION_NOTE_NAME")
	}

	if noteName == "" {
		glog.Fatalf("No note name was specified")
	}

	if attestationProject == "" {
		attestationProject = os.Getenv("ATTESTATION_PROJECT")
	}

	if !isFlagPassed("overwrite") && os.Getenv("ATTESTATION_OVERWRITE") != "" {
		overwrite, err = strconv.ParseBool(os.Getenv("ATTESTATION_OVERWRITE"))
		if err != nil {
			glog.Fatalf("failed to parse boolean from  ATTESTATION_OVERWRITE, %s", err)
		}
	}

	if kmsKeyName == "" {
		kmsKeyName = os.Getenv("ATTESTATION_KMS_KEY")
	}

	if kmsKeyName == "" {
		glog.Fatalf("no kms key is specified")
	}

	if digestAlgorithm == "" {
		digestAlgorithm = os.Getenv("ATTESTATION_DIGEST_ALGORITHM")
	}

	if digestAlgorithm == "" {
		glog.Fatalf("no message digest algorithm is specified")
	}

	err = util.CheckNoteName(noteName)
	if err != nil {
		glog.Fatalf("note name '%s' is invalid %s", noteName, err)
	}

	client, err = containeranalysis.New()
	if err != nil {
		glog.Fatalf("Could not initialize the container analysis client, %s", err)
	}

	grafeas, err = ca.NewGrafeasV1Beta1Client(context.Background())
	if err != nil {
		glog.Fatalf("Could not initialize the grafeas client, %s", err)
	}

	kmsSigner, err = signer.NewCloudKmsSigner(kmsKeyName, signer.DigestAlgorithm(digestAlgorithm))
	if err != nil {
		glog.Fatalf("Creating kms signer failed, %s", err)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	http.HandleFunc("/check", check)
	http.HandleFunc("/check-and-sign", checkAndSign)
	http.HandleFunc("/event", containerAnalysisEvent)

	glog.Infof("listening on port %s", port)
	err = http.ListenAndServe(":"+port, nil)
	if err != nil {
		glog.Fatalf("server stopped with error, %s", err)
	}
}
