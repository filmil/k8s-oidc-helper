package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/filmil/k8s-oidc-helper/internal/helper"
	"github.com/filmil/k8s-oidc-helper/internal/oidc"
	flag "github.com/spf13/pflag"
	viper "github.com/spf13/viper"
)

func main() {
	var config oidc.Config
	flag.BoolVarP(&config.Version, "version", "v", false, "Print version and exit")
	flag.BoolVarP(&config.Open, "open", "o", true, "Open the oauth approval URL in the browser")
	flag.StringVar(&config.ClientID, "client-id", "", "The ClientID for the application")
	flag.StringVar(&config.ClientSecret, "client-secret", "", "The ClientSecret for the application")
	flag.StringVarP(&config.ConfigFile, "config", "c", "", "Path to a json file containing your application's ClientID and ClientSecret. Supercedes the --client-id and --client-secret flags.")
	flag.BoolVarP(&config.Write, "write", "w", false, "Write config to file. Merges in the specified file")
	flag.StringVar(&config.KubeconfigFile, "file", "", "The file to write to. If not specified, `~/.kube/config` is used")

	var urlTpl oidc.UrlValues
	flag.StringVar(&urlTpl.URLPath, "oauth-url", "https://accounts.google.com/o/oauth2/auth", "The identity provider URL")
	flag.StringVar(&urlTpl.Scope, "scope", "openid+email+profile", "The scope to request from the identity provider")

	var endpoints helper.Endpoints
	flag.StringVar(&endpoints.TokenEndpoint, "oauth-token-endpoint", "https://www.googleapis.com/oauth2/v3/token", "The endpoint to use to obtain the oauth token")
	flag.StringVar(&endpoints.UserInfoEndpoint, "oauth-userinfo-endpoint", "https://www.googleapis.com/oauth2/v1/userinfo", "The endpoint to use to obtain the userinfo")

	viper.BindPFlags(flag.CommandLine)
	viper.SetEnvPrefix("k8s-oidc-helper")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	flag.Parse()

	if err := oidc.Run(config, urlTpl, endpoints); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
