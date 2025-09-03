package backends

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/argoproj-labs/argocd-vault-plugin/pkg/utils"
	"github.com/cyberark/conjur-api-go/conjurapi"
)

var fetchAllMaxSecrets = 1000

type ConjurAPIClient interface {
	Resources(filter *conjurapi.ResourceFilter) ([]map[string]interface{}, error)
	RetrieveBatchSecrets(ids []string) (map[string][]byte, error)
	RetrieveSecret(path string) ([]byte, error)
	RetrieveSecretWithVersion(path string, version int) ([]byte, error)
}

type CyberArkSecretsManager struct {
	client ConjurAPIClient
}

func NewCyberArkSecretsManagerBackend(client ConjurAPIClient) *CyberArkSecretsManager {
	return &CyberArkSecretsManager{
		client: client,
	}
}

// Login does nothing since Cyberark Secrets Manager client is setup on instantiation
func (csm *CyberArkSecretsManager) Login() error {
	return nil
}

// GetSecrets returns the data for all secrets of a specific type of a group in Cyberark Secrets Manager
func (csm *CyberArkSecretsManager) GetSecrets(path string, version string, annotations map[string]string) (map[string]interface{}, error) {
	allResourcePaths := []string{}
	for offset := 0; ; offset += 100 {
		resFilter := &conjurapi.ResourceFilter{
			Kind:   "variable",
			Limit:  100,
			Offset: offset,
			Search: path,
		}
		resources, err := csm.client.Resources(resFilter)
		if err != nil {
			return nil, fmt.Errorf("error fetching resources: %w", err)
		}

		for _, candidate := range resources {
			allResourcePaths = append(allResourcePaths, candidate["id"].(string))
		}

		// If we have less than 100 resources, we reached the last page
		if len(resources) < 100 {
			break
		}

		// Limit the maximum number of secrets we can fetch to prevent DoS
		if len(allResourcePaths) >= fetchAllMaxSecrets {
			break
		}
	}

	if len(allResourcePaths) == 0 {
		return nil, fmt.Errorf("no variables to retrieve")
	}

	// Retrieve all secrets in a single batch
	retrievedSecretsByFullIDs, err := csm.client.RetrieveBatchSecrets(allResourcePaths)
	if err != nil {
		return nil, fmt.Errorf("error retrieving batch secrets: %w", err)
	}

	// Normalise secret IDs from batch secrets back to <variable_id>
	var retrievedSecrets = make(map[string]interface{})
	for id, secret := range retrievedSecretsByFullIDs {
		retrievedSecrets[NormaliseVariableId(id)] = string(secret)
		delete(retrievedSecretsByFullIDs, id)
	}

	if len(retrievedSecrets) == 0 {
		return nil, fmt.Errorf("no secrets found for given path")
	}
	return retrievedSecrets, nil
}

// GetIndividualSecret will get the specific secret (placeholder) from the SM backend
// This requires listing the secrets of the group to obtain the id, and then using that to grab the one secret's payload
func (csm *CyberArkSecretsManager) GetIndividualSecret(kvpath, secretRef, version string, annotations map[string]string) (interface{}, error) {
	var retrievedSecret interface{}
	var err error

	secretPath := kvpath + "/" + secretRef

	// If version is specified, retrieve with version
	if version != "" {
		numberVersion, err := strconv.Atoi(version)
		if err != nil {
			return nil, fmt.Errorf("invalid version format: %s", version)
		}
		retrievedSecret, err = csm.client.RetrieveSecretWithVersion(secretPath, numberVersion)
	} else {
		// Otherwise, retrieve the latest version
		retrievedSecret, err = csm.client.RetrieveSecret(secretPath)
	}

	if err != nil {
		return nil, fmt.Errorf("error retrieving secret from path '%s': %w", secretPath, err)
	}

	// Convert to string if it's a byte slice (assuming that's the expected behavior)
	switch v := retrievedSecret.(type) {
	case []byte:
		return string(v), nil
	case string:
		return v, nil
	default:
		return nil, fmt.Errorf("unexpected secret type: %T", v)
	}
}

func NormaliseVariableId(fullVariableId string) string {
	variableIdParts := strings.SplitN(fullVariableId, ":", 3)
	if len(variableIdParts) == 3 {
		splitD := strings.Split(variableIdParts[2], "/")
		utils.VerboseToStdErr("secret variable :: %v", splitD[len(splitD)-1])
		return splitD[len(splitD)-1]
	}
	return fullVariableId
}
