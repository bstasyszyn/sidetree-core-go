/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package restapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/diddochandler"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/dochandler"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

const (
	url       = "localhost:8080"
	clientURL = "http://" + url
	namespace = "did:sidetree:"
)

const (
	didID = namespace + "EiDOQXC2GnoVyHwIRbjhLx_cNc6vmZaS04SZjZdlLLAPRg=="

	sampleID        = sampleNamespace + "EiDOQXC2GnoVyHwIRbjhLx_cNc6vmZaS04SZjZdlLLAPRg=="
	sampleNamespace = "sample:sidetree:"
	samplePath      = "/sample"

	createRequest = `{
  "header": {
    "operation": "create",
    "kid": "#key1",
    "alg": "ES256K"
  },
  "payload": "ewogICJAY29udGV4dCI6ICJodHRwczovL3czaWQub3JnL2RpZC92MSIsCiAgInB1YmxpY0tleSI6IFt7CiAgICAiaWQiOiAiI2tleTEiLAogICAgInR5cGUiOiAiU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOCIsCiAgICAicHVibGljS2V5SGV4IjogIjAyZjQ5ODAyZmIzZTA5YzZkZDQzZjE5YWE0MTI5M2QxZTBkYWQwNDRiNjhjZjgxY2Y3MDc5NDk5ZWRmZDBhYTlmMSIKICB9XSwKICAic2VydmljZSI6IFt7CiAgICAiaWQiOiAiSWRlbnRpdHlIdWIiLAogICAgInR5cGUiOiAiSWRlbnRpdHlIdWIiLAogICAgInNlcnZpY2VFbmRwb2ludCI6IHsKICAgICAgIkBjb250ZXh0IjogInNjaGVtYS5pZGVudGl0eS5mb3VuZGF0aW9uL2h1YiIsCiAgICAgICJAdHlwZSI6ICJVc2VyU2VydmljZUVuZHBvaW50IiwKICAgICAgImluc3RhbmNlIjogWyJkaWQ6YmFyOjQ1NiIsICJkaWQ6emF6Ojc4OSJdCiAgICB9CiAgfV0KfQo=",
  "signature": "mAJp4ZHwY5UMA05OEKvoZreRo0XrYe77s3RLyGKArG85IoBULs4cLDBtdpOToCtSZhPvCC2xOUXMGyGXDmmEHg"
}
`
)

func TestRESTAPI(t *testing.T) {
	didDocHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace)
	sampleDocHandler := mocks.NewMockDocumentHandler().WithNamespace(sampleNamespace)

	s := newRESTService(
		url,
		diddochandler.NewUpdateHandler(didDocHandler),
		diddochandler.NewResolveHandler(didDocHandler),
		newSampleUpdateHandler(sampleDocHandler),
		newsampleResolveHandler(sampleDocHandler),
	)
	s.start()
	defer s.stop()

	t.Run("Create DID doc", func(t *testing.T) {
		request := &model.Request{}
		err := json.Unmarshal([]byte(createRequest), request)
		require.NoError(t, err)

		resp, err := httpPut(t, clientURL+diddochandler.Path, request)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.NotNil(t, resp.Body)

		doc, ok := resp.Body.(map[string]interface{})
		require.True(t, ok)
		require.Equal(t, didID, doc["id"])
	})
	t.Run("Resolve DID doc", func(t *testing.T) {
		resp, err := httpGet(t, clientURL+diddochandler.Path+"/"+didID)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.NotNil(t, resp.Body)

		doc, ok := resp.Body.(map[string]interface{})
		require.True(t, ok)
		require.Equal(t, didID, doc["id"])
	})
	t.Run("Create sample doc", func(t *testing.T) {
		request := &model.Request{}
		err := json.Unmarshal([]byte(createRequest), request)
		require.NoError(t, err)

		resp, err := httpPut(t, clientURL+samplePath, request)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.NotNil(t, resp.Body)

		doc, ok := resp.Body.(map[string]interface{})
		require.True(t, ok)
		require.Equal(t, sampleID, doc["id"])
	})
	t.Run("Resolve sample doc", func(t *testing.T) {
		resp, err := httpGet(t, clientURL+samplePath+"/"+sampleID)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.NotNil(t, resp.Body)

		doc, ok := resp.Body.(map[string]interface{})
		require.True(t, ok)
		require.Equal(t, sampleID, doc["id"])
	})
}

// httpPut sends a regular POST request to the sidetree-node
// - If post request has operation "create" then return sidetree document else no response
func httpPut(t *testing.T, url string, req *model.Request) (*model.Response, error) {
	client := &http.Client{}
	b, err := json.Marshal(req)
	require.NoError(t, err)

	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(b))
	require.NoError(t, err)

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	require.NoError(t, err)

	return handleHttpResp(t, resp)
}

// httpGet send a regular GET request to the sidetree-node and expects 'side tree document' argument as a response
func httpGet(t *testing.T, url string) (*model.Response, error) {
	client := &http.Client{}
	resp, err := client.Get(url)
	require.NoError(t, err)
	return handleHttpResp(t, resp)
}

func handleHttpResp(t *testing.T, resp *http.Response) (*model.Response, error) {
	if status := resp.StatusCode; status != http.StatusOK {
		r := &model.Error{}
		decode(t, resp, r)
		return nil, fmt.Errorf(r.Message)
	}

	r := &model.Response{}
	decode(t, resp, r)
	return r, nil
}

func decode(t *testing.T, response *http.Response, v interface{}) {
	respBytes, err := ioutil.ReadAll(response.Body)
	require.NoError(t, err)

	fmt.Printf("Decoding: %s\n", respBytes)
	err = json.NewDecoder(strings.NewReader(string(respBytes))).Decode(v)
	require.NoError(t, err)
}

type restService struct {
	httpServer *http.Server
}

func newRESTService(url string, handlers ...common.HTTPHandler) *restService {
	router := mux.NewRouter()
	for _, handler := range handlers {
		router.HandleFunc(handler.Path(), handler.Handler()).Methods(handler.Method())
	}
	return &restService{
		httpServer: &http.Server{
			Addr:    url,
			Handler: router,
		},
	}
}

func (s *restService) start() {
	go func() {
		err := s.httpServer.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			panic(fmt.Sprintf("failed to start Sidetree REST service on [%s]: %s", s.httpServer.Addr, err))
		}
	}()
}

func (s *restService) stop() {
	err := s.httpServer.Shutdown(context.Background())
	if err != nil {
		panic(fmt.Sprintf("failed to stop Sidetree REST service on [%s]: %s", s.httpServer.Addr, err))
	}
}

type sampleUpdateHandler struct {
	*dochandler.UpdateHandler
}

func newSampleUpdateHandler(processor dochandler.Processor) *sampleUpdateHandler {
	return &sampleUpdateHandler{
		UpdateHandler: dochandler.NewUpdateHandler(processor),
	}
}

// Path returns the context path
func (h *sampleUpdateHandler) Path() string {
	return samplePath
}

// Method returns the HTTP method
func (h *sampleUpdateHandler) Method() string {
	return http.MethodPost
}

// Handler returns the handler
func (h *sampleUpdateHandler) Handler() common.HTTPRequestHandler {
	return h.Update
}

type sampleResolveHandler struct {
	*dochandler.ResolveHandler
}

func newsampleResolveHandler(resolver dochandler.Resolver) *sampleResolveHandler {
	return &sampleResolveHandler{
		ResolveHandler: dochandler.NewResolveHandler(resolver),
	}
}

// Path returns the context path
func (h *sampleResolveHandler) Path() string {
	return samplePath + "/{id}"
}

// Method returns the HTTP method
func (h *sampleResolveHandler) Method() string {
	return http.MethodGet
}

// Handler returns the handler
func (h *sampleResolveHandler) Handler() common.HTTPRequestHandler {
	return h.Resolve
}
