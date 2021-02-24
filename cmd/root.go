package cmd

/*
Copyright © 2021 Jose Cortes

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"

	"github.com/josecv/ebpf-userspace-exporter/pkg/config"
	"github.com/josecv/ebpf-userspace-exporter/pkg/server"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
	yaml "gopkg.in/yaml.v2"
	"io/ioutil"
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "ebpf-userspace-exporter",
	Short: "Runs USDT ebpf probes as a sidecar to a k8s pod and exports them into prometheus",
	Long:  `Runs USDT ebpf probes as a sidecar to a k8s pod and exports them into prometheus`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	RunE: func(cmd *cobra.Command, args []string) error {
		configPath := viper.GetString("probe-config")
		listenAddr := viper.GetString("listen-address")
		metricsPath := viper.GetString("metrics-path")
		yamlFile, err := ioutil.ReadFile(configPath)
		if err != nil {
			return fmt.Errorf("Error reading %s: %s", configPath, err)
		}
		config := config.Config{}
		err = yaml.Unmarshal(yamlFile, &config)
		if err != nil {
			return fmt.Errorf("Error unmarshaling %s: %s", configPath, err)
		}
		server.Serve(listenAddr, metricsPath, config)
		// Should not be reached
		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)

	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.ebpf-userspace-exporter.yaml)")

	rootCmd.Flags().StringP("probe-config", "c", "", "The config file for probes and attached programs; not to be confused with the exporter's config file itself (--config)")
	rootCmd.MarkFlagRequired("probe-config")
	viper.BindPFlag("probe-config", rootCmd.Flags().Lookup("probe-config"))

	rootCmd.Flags().StringP("listen-address", "l", "0.0.0.0:8080", "Address to listen on for HTTP requests")
	viper.BindPFlag("listen-address", rootCmd.Flags().Lookup("listen-address"))

	rootCmd.Flags().StringP("metrics-path", "m", "/metrics", "Path under which to serve metrics")
	viper.BindPFlag("metrics-path", rootCmd.Flags().Lookup("metrics-path"))
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".ebpf-userspace-exporter" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".ebpf-userspace-exporter")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}
