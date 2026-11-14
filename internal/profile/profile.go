// Package profile holds the rules for profile fields that people (if their
// organisation allows) and admins can change: name, username (the part of
// the email before @) and profile picture.
package profile

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var usernameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$`)

const UsernameHelp = "Use lowercase letters, numbers, dots, dashes or underscores, like j.smith"

func NormaliseUsername(u string) string { return strings.ToLower(strings.TrimSpace(u)) }

func ValidUsername(u string) bool { return usernameRE.MatchString(u) }

// ValidName: not empty, not absurdly long.
func ValidName(n string) bool {
	n = strings.TrimSpace(n)
	return n != "" && len(n) <= 200
}

// MaxPictureBytes is the largest picture accepted (2 MB).
const MaxPictureBytes = 2 << 20

var ErrPicture = errors.New("Choose a PNG, JPEG or GIF picture, under 2 MB and at most 4096 pixels across")

// CheckPicture makes sure data is a real image of an allowed type and size,
// and returns its content type (from the bytes, not what the browser said).
func CheckPicture(data []byte) (string, error) {
	if len(data) == 0 || len(data) > MaxPictureBytes {
		return "", ErrPicture
	}
	contentType := http.DetectContentType(data)
	switch contentType {
	case "image/png", "image/jpeg", "image/gif":
	default:
		return "", ErrPicture
	}
	cfg, _, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil || cfg.Width < 1 || cfg.Height < 1 || cfg.Width > 4096 || cfg.Height > 4096 {
		return "", ErrPicture
	}
	return contentType, nil
}

// PictureURL is where a profile picture is served (nil: none). The version
// in the query changes with the picture, so it can be cached for long.
func PictureURL(issuer, userID string, updated *time.Time) string {
	if updated == nil {
		return ""
	}
	return fmt.Sprintf("%s/pictures/%s?v=%d", issuer, userID, updated.Unix())
}
