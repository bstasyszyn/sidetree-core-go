/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package patch

import (
	"encoding/json"
	"errors"
	"fmt"

	jsonpatch "github.com/evanphx/json-patch"

	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
)

// Action defines action of document patch
type Action string

const (
	// Replace captures enum value "replace"
	Replace Action = "replace"

	// AddPublicKeys captures enum value "add-public-keys"
	AddPublicKeys Action = "add-public-keys"

	// RemovePublicKeys captures enum value "remove-public-keys"
	RemovePublicKeys Action = "remove-public-keys"

	//AddServiceEndpoints captures "add-service-endpoints"
	AddServiceEndpoints Action = "add-service-endpoints"

	//RemoveServiceEndpoints captures "remove-service-endpoints"
	RemoveServiceEndpoints Action = "remove-service-endpoints"

	// JSONPatch captures enum value "json-patch"
	JSONPatch Action = "ietf-json-patch"
)

// Key defines key that will be used to get document patch information
type Key string

const (

	// DocumentKey captures  "document" key
	DocumentKey Key = "document"

	// PatchesKey captures "patches" key
	PatchesKey Key = "patches"

	// PublicKeys captures "public_keys" key
	PublicKeys Key = "public_keys"

	//ServiceEndpointsKey captures "service_endpoints" key
	ServiceEndpointsKey Key = "service_endpoints"

	//ServiceEndpointIdsKey captures "ids" key
	ServiceEndpointIdsKey Key = "ids"

	// ActionKey captures "action" key
	ActionKey Key = "action"
)

// Patch defines generic patch structure
type Patch map[Key]interface{}

// NewReplacePatch creates new replace patch
func NewReplacePatch(doc string) (Patch, error) {
	parsed, err := document.FromBytes([]byte(doc))
	if err != nil {
		return nil, err
	}

	if err := validateDocument(parsed); err != nil {
		return nil, err
	}

	patch := make(Patch)
	patch[ActionKey] = Replace
	patch[DocumentKey] = parsed.JSONLdObject()

	return patch, nil
}

// NewJSONPatch creates new generic update patch (will be used for generic updates)
func NewJSONPatch(patches string) (Patch, error) {
	if err := validatePatches([]byte(patches)); err != nil {
		return nil, err
	}

	var generic []interface{}
	err := json.Unmarshal([]byte(patches), &generic)
	if err != nil {
		return nil, err
	}

	patch := make(Patch)
	patch[ActionKey] = JSONPatch
	patch[PatchesKey] = generic

	return patch, nil
}

// NewAddPublicKeysPatch creates new patch for adding public keys
func NewAddPublicKeysPatch(publicKeys string) (Patch, error) {
	pubKeys, err := getPublicKeys(publicKeys)
	if err != nil {
		return nil, err
	}

	patch := make(Patch)
	patch[ActionKey] = AddPublicKeys
	patch[PublicKeys] = pubKeys

	return patch, nil
}

// NewRemovePublicKeysPatch creates new patch for removing public keys
func NewRemovePublicKeysPatch(publicKeyIds string) (Patch, error) {
	ids, err := getStringArray(publicKeyIds)
	if err != nil {
		return nil, fmt.Errorf("public key ids not string array: %s", err.Error())
	}

	if len(ids) == 0 {
		return nil, errors.New("missing public key ids")
	}

	patch := make(Patch)
	patch[ActionKey] = RemovePublicKeys
	patch[PublicKeys] = getGenericArray(ids)

	return patch, nil
}

// NewAddServiceEndpointsPatch creates new patch for adding service endpoints
func NewAddServiceEndpointsPatch(serviceEndpoints string) (Patch, error) {
	services, err := getServices(serviceEndpoints)
	if err != nil {
		return nil, err
	}

	patch := make(Patch)
	patch[ActionKey] = AddServiceEndpoints
	patch[ServiceEndpointsKey] = services

	return patch, nil
}

// NewRemoveServiceEndpointsPatch creates new patch for removing service endpoints
func NewRemoveServiceEndpointsPatch(serviceEndpointIds string) (Patch, error) {
	ids, err := getStringArray(serviceEndpointIds)
	if err != nil {
		return nil, fmt.Errorf("service ids not string array: %s", err.Error())
	}

	if len(ids) == 0 {
		return nil, errors.New("missing service ids")
	}

	patch := make(Patch)
	patch[ActionKey] = RemoveServiceEndpoints
	patch[ServiceEndpointIdsKey] = getGenericArray(ids)

	return patch, nil
}

// GetValue returns value for specified key or nil if not found
func (p Patch) GetValue(key Key) interface{} {
	return p[key]
}

// GetAction returns string value for specified key or "" if not found or wrong type
func (p Patch) GetAction() Action {
	entry := p[ActionKey]
	actionStr, ok := entry.(string)
	if ok {
		return Action(actionStr)
	}

	return p[ActionKey].(Action)
}

// Bytes returns byte representation of patch
func (p Patch) Bytes() ([]byte, error) {
	return docutil.MarshalCanonical(p)
}

// Validate validates patch
func (p Patch) Validate() error {
	action, err := p.parseAction()
	if err != nil {
		return err
	}

	switch action {
	case Replace:
		return p.validateReplace()
	case JSONPatch:
		return p.validateJSON()
	case AddPublicKeys:
		return p.validateAddPublicKeys()
	case RemovePublicKeys:
		return p.validateRemovePublicKeys()
	case AddServiceEndpoints:
		return p.validateAddServiceEndpoints()
	case RemoveServiceEndpoints:
		return p.validateRemoveServiceEndpoints()
	}

	return fmt.Errorf("action '%s' is not supported", action)
}

// JSONLdObject returns map that represents JSON LD Object
func (p Patch) JSONLdObject() map[Key]interface{} {
	return p
}

// FromBytes parses provided data into document patch
func FromBytes(data []byte) (Patch, error) {
	patch := make(Patch)
	err := json.Unmarshal(data, &patch)
	if err != nil {
		return nil, err
	}

	if err := patch.Validate(); err != nil {
		return nil, err
	}

	return patch, nil
}

func stringEntry(entry interface{}) string {
	if entry == nil {
		return ""
	}
	id, ok := entry.(string)
	if !ok {
		return ""
	}
	return id
}

func validateDocument(doc document.Document) error {
	if doc.ID() != "" {
		return errors.New("document must NOT have the id property")
	}

	return document.ValidatePublicKeys(doc.PublicKeys())
}

func validatePatches(patches []byte) error {
	_, err := jsonpatch.DecodePatch(patches)
	if err != nil {
		return err
	}

	// TODO: We should probably not allow updating keys and services using this patch #175

	return nil
}

func getPublicKeys(publicKeys string) (interface{}, error) {
	// create an empty did document with public keys
	pkDoc, err := document.DidDocumentFromBytes([]byte(fmt.Sprintf(`{"%s":%s}`, document.PublicKeyProperty, publicKeys)))
	if err != nil {
		return nil, fmt.Errorf("public keys invalid: %s", err.Error())
	}

	pubKeys := pkDoc.PublicKeys()
	err = document.ValidatePublicKeys(pubKeys)
	if err != nil {
		return nil, err
	}

	return pkDoc[document.PublicKeyProperty], nil
}

func getServices(serviceEndpoints string) (interface{}, error) {
	// create an empty did document with service endpoints
	svcDocStr := fmt.Sprintf(`{"%s":%s}`, document.ServiceProperty, serviceEndpoints)
	svcDoc, err := document.DidDocumentFromBytes([]byte(svcDocStr))
	if err != nil {
		return nil, fmt.Errorf("services invalid: %s", err.Error())
	}

	// Add service validation here similar to public keys

	return svcDoc[document.ServiceProperty], nil
}

func (p *Patch) parseAction() (Action, error) {
	entry := p.GetValue(ActionKey)
	if entry == nil {
		return "", errors.New("patch is missing action property")
	}

	switch v := entry.(type) {
	case Action:
		return v, nil
	case string:
		return Action(v), nil
	default:
		return "", fmt.Errorf("action type not supported: %s", v)
	}
}

func (p Patch) getRequiredMap(key Key) (map[string]interface{}, error) {
	entry := p.GetValue(key)
	if entry == nil {
		return nil, fmt.Errorf("%s patch is missing %s", p.GetAction(), key)
	}

	required, ok := entry.(map[string]interface{})
	if !ok {
		return nil, errors.New("unexpected interface for document")
	}

	return required, nil
}

func (p Patch) getRequiredArray(key Key) ([]interface{}, error) {
	entry := p.GetValue(key)
	if entry == nil {
		return nil, fmt.Errorf("%s patch is missing %s", p.GetAction(), key)
	}

	arr, ok := entry.([]interface{})
	if !ok {
		return nil, errors.New("expected array of interfaces")
	}

	if len(arr) == 0 {
		return nil, errors.New("required array is empty")
	}

	return arr, nil
}

func (p Patch) validateReplace() error {
	doc, err := p.getRequiredMap(DocumentKey)
	if err != nil {
		return err
	}

	return validateDocument(document.FromJSONLDObject(doc))
}

func (p Patch) validateJSON() error {
	patches, err := p.getRequiredArray(PatchesKey)
	if err != nil {
		return err
	}

	patchesBytes, err := json.Marshal(patches)
	if err != nil {
		return err
	}

	return validatePatches(patchesBytes)
}

func (p Patch) validateAddPublicKeys() error {
	_, err := p.getRequiredArray(PublicKeys)
	if err != nil {
		return err
	}

	publicKeys := document.ParsePublicKeys(p.GetValue(PublicKeys))
	return document.ValidatePublicKeys(publicKeys)
}

func (p Patch) validateRemovePublicKeys() error {
	_, err := p.getRequiredArray(PublicKeys)
	return err
}

func (p Patch) validateAddServiceEndpoints() error {
	_, err := p.getRequiredArray(ServiceEndpointsKey)
	return err
}

func (p Patch) validateRemoveServiceEndpoints() error {
	_, err := p.getRequiredArray(ServiceEndpointIdsKey)
	return err
}

func getStringArray(arr string) ([]string, error) {
	var values []string
	err := json.Unmarshal([]byte(arr), &values)
	if err != nil {
		return nil, err
	}

	return values, nil
}

func getGenericArray(arr []string) []interface{} {
	var values []interface{}
	for _, v := range arr {
		values = append(values, v)
	}
	return values
}
