package cmd

import (
	"github.com/spf13/cobra"
)

var RootCmd = &cobra.Command{
	Use:   "krl",
	Short: "Kraaler is an extendable user-perspective web crawler",
	Long:  "Kraaler is an extendable user-perspective web crawler based on Chromium",
}

// func getDataPath(name string) string {
// 	return filepath.Join(viper.Get(DATA_DIR).(string), viper.Get(name).(string))
// }

// func screenPath() string {
// 	return getDataPath(SCREEN_DIR)
// }

// func bodiesPath() string {
// 	return getDataPath(BODY_DIR)
// }

// func dbPath() string {
// 	return getDataPath(DB_FILE)
// }
