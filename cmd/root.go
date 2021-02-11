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

	"github.com/josecv/ebpf-usdt-sidecar/internal"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "ebpf-usdt-sidecar",
	Short: "Runs USDT ebpf probes as a sidecar to a k8s pod",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	RunE: func(cmd *cobra.Command, args []string) error {
		pid := viper.GetInt("pid")
		path := viper.GetString("bcc-program")
		probe := viper.GetString("probe")
		fnName := viper.GetString("fn-name")
		return internal.Attach(pid, probe, fnName, path)
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

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.ebpf-usdt-sidecar.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().IntP("pid", "p", 0, "The pid to bind to")
	rootCmd.MarkFlagRequired("pid")
	viper.BindPFlag("pid", rootCmd.Flags().Lookup("pid"))

	rootCmd.Flags().StringP("probe", "r", "", "The probe to bind to")
	rootCmd.MarkFlagRequired("probe")
	viper.BindPFlag("probe", rootCmd.Flags().Lookup("probe"))

	rootCmd.Flags().StringP("fn-name", "f", "", "The fn-name to bind to")
	rootCmd.MarkFlagRequired("fn-name")
	viper.BindPFlag("fn-name", rootCmd.Flags().Lookup("fn-name"))

	rootCmd.Flags().StringP("bcc-program", "b", "", "Path to the bcc program to run")
	rootCmd.MarkFlagRequired("bcc-program")
	viper.BindPFlag("bcc-program", rootCmd.Flags().Lookup("bcc-program"))
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

		// Search config in home directory with name ".ebpf-usdt-sidecar" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".ebpf-usdt-sidecar")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}
