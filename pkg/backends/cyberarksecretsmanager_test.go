package backends_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/argoproj-labs/argocd-vault-plugin/pkg/backends"
	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockConjurClient is a mock implementation of ConjurAPIClient
type MockConjurClient struct {
	mock.Mock
}

func (m *MockConjurClient) Resources(filter *conjurapi.ResourceFilter) ([]map[string]interface{}, error) {
	args := m.Called(filter)
	return args.Get(0).([]map[string]interface{}), args.Error(1)
}

func (m *MockConjurClient) RetrieveBatchSecrets(ids []string) (map[string][]byte, error) {
	args := m.Called(ids)
	return args.Get(0).(map[string][]byte), args.Error(1)
}

func (m *MockConjurClient) RetrieveSecret(path string) ([]byte, error) {
	args := m.Called(path)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockConjurClient) RetrieveSecretWithVersion(path string, version int) ([]byte, error) {
	args := m.Called(path, version)
	return args.Get(0).([]byte), args.Error(1)
}

func TestCyberArkSecretsManager(t *testing.T) {
	t.Run("Login", testLogin)
	t.Run("GetSecrets", testGetSecrets)
	t.Run("GetIndividualSecret", testGetIndividualSecret)
	t.Run("NormaliseVariableId", testNormaliseVariableId)
}

func testLogin(t *testing.T) {
	mockClient := new(MockConjurClient)
	manager := backends.NewCyberArkSecretsManagerBackend(mockClient)
	err := manager.Login()
	assert.NoError(t, err)
}

func testGetSecrets(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockClient := new(MockConjurClient)
		mockResources := []map[string]interface{}{
			{"id": "some:prefix:variable/group/secret1"},
			{"id": "some:prefix:variable/group/secret2"},
		}
		mockSecrets := map[string][]byte{
			"some:prefix:variable/group/secret1": []byte("value1"),
			"some:prefix:variable/group/secret2": []byte("value2"),
		}
		mockClient.On("Resources", mock.Anything).Return(mockResources, nil).Once()
		mockClient.On("RetrieveBatchSecrets", mock.Anything).Return(mockSecrets, nil).Once()

		manager := backends.NewCyberArkSecretsManagerBackend(mockClient)
		secrets, err := manager.GetSecrets("group", "", nil)

		assert.NoError(t, err)
		assert.Equal(t, "value1", secrets["secret1"])
		assert.Equal(t, "value2", secrets["secret2"])
	})

	t.Run("NoResources", func(t *testing.T) {
		mockClient := new(MockConjurClient)
		mockClient.On("Resources", mock.Anything).Return([]map[string]interface{}{}, nil).Once()

		manager := backends.NewCyberArkSecretsManagerBackend(mockClient)
		secrets, err := manager.GetSecrets("group", "", nil)

		assert.Error(t, err)
		assert.Nil(t, secrets)
		assert.Contains(t, err.Error(), "no variables to retrieve")
	})

	t.Run("RetrieveBatchSecretsError", func(t *testing.T) {
		mockClient := new(MockConjurClient)
		mockClient.On("Resources", mock.Anything).Return([]map[string]interface{}{
			{"id": "some:prefix:variable/group/secret1"},
		}, nil).Once()
		mockClient.On("RetrieveBatchSecrets", mock.Anything).Return(map[string][]byte(nil), errors.New("batch secret fetch failed")).Once()

		manager := backends.NewCyberArkSecretsManagerBackend(mockClient)
		_, err := manager.GetSecrets("group", "", nil)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "error retrieving batch secrets")
		assert.Contains(t, err.Error(), "batch secret fetch failed")
	})

	t.Run("ResourceFetchError", func(t *testing.T) {
		mockClient := new(MockConjurClient)
		mockClient.On("Resources", mock.Anything).Return([]map[string]interface{}(nil), errors.New("fetch error")).Once()

		manager := backends.NewCyberArkSecretsManagerBackend(mockClient)
		_, err := manager.GetSecrets("group", "", nil)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "fetch error")
	})

	t.Run("NoSecretsFound", func(t *testing.T) {
		mockClient := new(MockConjurClient)
		mockResources := []map[string]interface{}{
			{"id": "some:prefix:variable/group/secret1"},
			{"id": "some:prefix:variable/group/secret2"},
		}
		mockClient.On("Resources", mock.Anything).Return(mockResources, nil).Once()
		mockClient.On("RetrieveBatchSecrets", mock.Anything).Return(map[string][]byte{}, nil).Once()

		manager := backends.NewCyberArkSecretsManagerBackend(mockClient)
		secrets, err := manager.GetSecrets("group", "", nil)

		assert.Error(t, err)
		assert.Nil(t, secrets)
		assert.Contains(t, err.Error(), "no secrets found for given path")
	})
	t.Run("MaxSecretsLimitReached", func(t *testing.T) {
		mockClient := new(MockConjurClient)

		fetchAllMaxSecrets := 1000
		var mockAllResources []map[string]interface{}
		for i := 0; i < fetchAllMaxSecrets+1; i++ {
			mockAllResources = append(mockAllResources, map[string]interface{}{
				"id": fmt.Sprintf("some:prefix:variable/group/secret%d", i+1),
			})
		}

		mockClient.On("Resources", mock.Anything).Return(mockAllResources, nil).Once()

		mockSecrets := make(map[string][]byte)
		for i := 0; i < fetchAllMaxSecrets; i++ {
			mockSecrets[fmt.Sprintf("some:prefix:variable/group/secret%d", i+1)] = []byte(fmt.Sprintf("value%d", i+1))
		}
		mockClient.On("RetrieveBatchSecrets", mock.Anything).Return(mockSecrets, nil).Once()

		manager := backends.NewCyberArkSecretsManagerBackend(mockClient)
		secrets, err := manager.GetSecrets("group", "", nil)

		assert.NoError(t, err)
		assert.Len(t, secrets, fetchAllMaxSecrets)
	})

}

func testGetIndividualSecret(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockClient := new(MockConjurClient)
		mockClient.On("RetrieveSecret", "group/secret1").Return([]byte("latestValue"), nil).Once()

		manager := backends.NewCyberArkSecretsManagerBackend(mockClient)
		secret, err := manager.GetIndividualSecret("group", "secret1", "", nil)

		assert.NoError(t, err)
		assert.Equal(t, "latestValue", secret)
	})

	t.Run("WithVersion", func(t *testing.T) {
		mockClient := new(MockConjurClient)
		mockClient.On("RetrieveSecretWithVersion", "group/secret1", 2).Return([]byte("v2Value"), nil).Once()

		manager := backends.NewCyberArkSecretsManagerBackend(mockClient)
		secret, err := manager.GetIndividualSecret("group", "secret1", "2", nil)

		assert.NoError(t, err)
		assert.Equal(t, "v2Value", secret)
	})

	t.Run("InvalidVersion", func(t *testing.T) {
		mockClient := new(MockConjurClient)
		manager := backends.NewCyberArkSecretsManagerBackend(mockClient)
		_, err := manager.GetIndividualSecret("group", "secret1", "invalid", nil)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid version format")
	})
	t.Run("RetrieveSecretError", func(t *testing.T) {
		mockClient := new(MockConjurClient)
		mockClient.On("RetrieveSecret", "group/secret1").Return([]byte(nil), errors.New("secret retrieval failed")).Once()

		manager := backends.NewCyberArkSecretsManagerBackend(mockClient)
		_, err := manager.GetIndividualSecret("group", "secret1", "", nil)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "error retrieving secret from path 'group/secret1'")
		assert.Contains(t, err.Error(), "secret retrieval failed")
	})
}

func testNormaliseVariableId(t *testing.T) {
	t.Run("ValidFormat", func(t *testing.T) {
		input := "some:prefix:variable/group/secret-name"
		expected := "secret-name"
		result := backends.NormaliseVariableId(input)
		assert.Equal(t, expected, result)
	})

	t.Run("InvalidFormat", func(t *testing.T) {
		input := "invalid-id-format"
		expected := "invalid-id-format"
		result := backends.NormaliseVariableId(input)
		assert.Equal(t, expected, result)
	})
}
