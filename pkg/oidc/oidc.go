// Package oidc encapsulates the client-side (Relying Party) flow that can be
// used to obtain OIDC token ID from an OIDC IDP.
package oidc

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/filmil/k8s-oidc-helper/pkg/helper"
	"github.com/ghodss/yaml"
	k8s_runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	clientcmdlatest "k8s.io/client-go/tools/clientcmd/api/latest"
)

const Version = "v0.1.1-alpha.2"

// urlTemplate is the template URL for the OIDC IDP request.
var urlTemplate = template.Must(template.New("url").Parse("{{.URLPath}}?redirect_uri=urn:ietf:wg:oauth:2.0:oob&response_type=code&client_id={{.ClientID}}&scope={{.Scope}}&approval_prompt=force&access_type=offline"))

// UrlValues contains all values that will be substituted into the URL template.
type UrlValues struct {
	URLPath  string
	Scope    string
	ClientID string
}

type Config struct {
	// Version is set if only printing version was requested.
	Version bool

	// Open is set if opening a browser is requested.
	Open bool

	// ClientID is set to the value of client ID.
	ClientID string

	// ClientSecret is set to the value of client secret used.
	ClientSecret string

	// ConfigFile, if defined, is used to get ClientID and ClientSecret from.
	ConfigFile string

	// If set, the kubeconfig file is updated with the resulting settings.
	Write bool

	// KubeconfigFile is a kubeconfig file to write to.
	KubeconfigFile string
}

// Run goes through the OIDC flow for the user.
func Run(config Config, urlTpl UrlValues, endpoints helper.Endpoints) error {
	urlTpl.Scope = url.PathEscape(urlTpl.Scope)
	if config.Version {
		fmt.Printf("k8s-oidc-helper %s\n", Version)
		return nil
	}

	var gcf *helper.GoogleConfig
	var err error
	if configFile := config.ConfigFile; len(configFile) > 0 {
		gcf, err = helper.ReadConfig(configFile)
		if err != nil {
			return fmt.Errorf("Error reading config file %s: %s\n", configFile, err)
		}
	}

	var clientSecret string
	if gcf != nil {
		urlTpl.ClientID = gcf.ClientID
		clientSecret = gcf.ClientSecret
	} else {
		urlTpl.ClientID = config.ClientID
		clientSecret = config.ClientSecret
	}

	url := bytes.NewBuffer(nil)
	if err := urlTemplate.Execute(url, urlTpl); err != nil {
		fmt.Errorf("Error building request URL: %s\n", err)
	}

	helper.LaunchBrowser(config.Open, url.String())

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the code Google gave you: ")
	code, _ := reader.ReadString('\n')
	code = strings.TrimSpace(code)

	tokResponse, err := endpoints.GetToken(urlTpl.ClientID, clientSecret, code)
	if err != nil {
		return fmt.Errorf("Error getting tokens: %s\n", err)
	}

	email, err := endpoints.GetUserEmail(tokResponse.AccessToken)
	if err != nil {
		return fmt.Errorf("Error getting user email: %s\n", err)
	}

	authInfo := helper.GenerateAuthInfo(urlTpl.ClientID, clientSecret, tokResponse.IdToken, tokResponse.RefreshToken)
	k8sconfig := &clientcmdapi.Config{
		AuthInfos: map[string]*clientcmdapi.AuthInfo{email: authInfo},
	}

	if !config.Write {
		fmt.Println("\n# Add the following to your ~/.kube/config")

		json, err := k8s_runtime.Encode(clientcmdlatest.Codec, k8sconfig)
		if err != nil {
			return fmt.Errorf("unexpected error: %v", err)
		}
		output, err := yaml.JSONToYAML(json)
		if err != nil {
			return fmt.Errorf("unexpected error: %v", err)
		}
		fmt.Printf("%v", string(output))
		return nil
	}

	tempKubeConfig, err := ioutil.TempFile("", "")
	if err != nil {
		return fmt.Errorf("Could not create tempfile: %v", err)
	}
	defer os.Remove(tempKubeConfig.Name())
	clientcmd.WriteToFile(*k8sconfig, tempKubeConfig.Name())

	var kubeConfigPath string
	if config.KubeconfigFile == "" {
		usr, err := user.Current()
		if err != nil {
			return fmt.Errorf("Could not determine current: %v", err)
		}
		kubeConfigPath = filepath.Join(usr.HomeDir, ".kube", "config")
	} else {
		kubeConfigPath = config.KubeconfigFile
	}

	loadingRules := clientcmd.ClientConfigLoadingRules{
		Precedence: []string{tempKubeConfig.Name(), kubeConfigPath},
	}
	mergedConfig, err := loadingRules.Load()
	if err != nil {
		return fmt.Errorf("Could not merge configuration: %v", err)
	}

	clientcmd.WriteToFile(*mergedConfig, kubeConfigPath)
	fmt.Printf("Configuration has been written to %s\n", kubeConfigPath)
	return nil
}