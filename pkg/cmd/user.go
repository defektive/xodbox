package cmd

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/defektive/xodbox/pkg/model"
	"github.com/spf13/cobra"
)

var (
	userRoleAdmin bool
	userPassword  string
)

var userCmd = &cobra.Command{
	Use:   "user",
	Short: "Manage admin console users.",
	Long:  "Create and manage the users that can log into the embedded admin web UI.",
}

var userAddCmd = &cobra.Command{
	Use:   "add <username>",
	Short: "Create an admin console user (bootstrap the first admin).",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		password, generated, err := resolvePassword()
		if err != nil {
			return err
		}
		role := model.RoleUser
		if userRoleAdmin {
			role = model.RoleAdmin
		}
		u, err := model.CreateUser(args[0], password, role)
		if err != nil {
			return err
		}
		fmt.Printf("created user %q (role: %s)\n", u.Username, u.Role)
		printGeneratedPassword(generated, password)
		return nil
	},
}

var userListCmd = &cobra.Command{
	Use:   "list",
	Short: "List admin console users.",
	Run: func(cmd *cobra.Command, args []string) {
		users := model.ListUsers()
		if len(users) == 0 {
			fmt.Println("no users; create one with 'xodbox user add <name> --admin'")
			return
		}
		for _, u := range users {
			fmt.Printf("%d\t%s\t%s\n", u.ID, u.Username, u.Role)
		}
	},
}

var userPasswdCmd = &cobra.Command{
	Use:   "passwd <username>",
	Short: "Reset a user's password (revokes their active sessions).",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		u, err := model.UserByUsername(args[0])
		if err != nil {
			return fmt.Errorf("user %q not found", args[0])
		}
		password, generated, err := resolvePassword()
		if err != nil {
			return err
		}
		if err := u.SetPassword(password); err != nil {
			return err
		}
		model.DeleteUserSessions(u.ID)
		fmt.Printf("password updated for %q; active sessions revoked\n", u.Username)
		printGeneratedPassword(generated, password)
		return nil
	},
}

var userRmCmd = &cobra.Command{
	Use:   "rm <username>",
	Short: "Delete a user and their API keys and sessions.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		u, err := model.UserByUsername(args[0])
		if err != nil {
			return fmt.Errorf("user %q not found", args[0])
		}
		if err := model.DeleteUser(u.ID); err != nil {
			return err
		}
		fmt.Printf("deleted user %q\n", u.Username)
		return nil
	},
}

// resolvePassword uses the --password flag when given, otherwise generates a
// strong random password (returned so the caller can display it once).
func resolvePassword() (password string, generated bool, err error) {
	if userPassword != "" {
		return userPassword, false, nil
	}
	p, err := generatePassword()
	if err != nil {
		return "", false, err
	}
	return p, true, nil
}

func printGeneratedPassword(generated bool, password string) {
	if generated {
		fmt.Printf("password: %s\n", password)
		fmt.Println("store this now — it is not recoverable")
	}
}

func generatePassword() (string, error) {
	b := make([]byte, 18) // 144 bits -> 24 URL-safe chars
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func init() {
	userAddCmd.Flags().BoolVar(&userRoleAdmin, "admin", false, "grant the admin role")
	userAddCmd.Flags().StringVar(&userPassword, "password", "", "use this password instead of a generated one")
	userPasswdCmd.Flags().StringVar(&userPassword, "password", "", "use this password instead of a generated one")
	userCmd.AddCommand(userAddCmd, userListCmd, userPasswdCmd, userRmCmd)
	XodboxCmd.AddCommand(userCmd)
}
