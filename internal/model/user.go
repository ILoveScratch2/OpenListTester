package model

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/OpenListTeam/OpenList/internal/errs"
	"github.com/OpenListTeam/OpenList/pkg/utils"
	"github.com/OpenListTeam/OpenList/pkg/utils/random"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/pkg/errors"
	"golang.org/x/crypto/argon2"
)

const (
	GENERAL = iota
	GUEST   // only one exists
	ADMIN
)

const StaticHashSalt = "https://github.com/alist-org/alist"

type User struct {
	ID       uint   `json:"id" gorm:"primaryKey"`                      // unique key
	Username string `json:"username" gorm:"unique" binding:"required"` // username
	PwdHash  string `json:"-"`                                         // password hash
	PwdTS    int64  `json:"-"`                                         // password timestamp
	Salt     string `json:"-"`                                         // unique salt
	Password string `json:"password"`                                  // password
	BasePath string `json:"base_path"`                                 // base path
	Role     int    `json:"role"`                                      // user's role
	Disabled bool   `json:"disabled"`
	// Determine permissions by bit
	//   0:  can see hidden files
	//   1:  can access without password
	//   2:  can add offline download tasks
	//   3:  can mkdir and upload
	//   4:  can rename
	//   5:  can move
	//   6:  can copy
	//   7:  can remove
	//   8:  webdav read
	//   9:  webdav write
	//   10: ftp/sftp login and read
	//   11: ftp/sftp write
	//   12: can read archives
	//   13: can decompress archives
	Permission int32  `json:"permission"`
	OtpSecret  string `json:"-"`
	SsoID      string `json:"sso_id"` // unique by sso platform
	Authn      string `gorm:"type:text" json:"-"`
}

func (u *User) IsGuest() bool {
	return u.Role == GUEST
}

func (u *User) IsAdmin() bool {
	return u.Role == ADMIN
}

func (u *User) ValidateRawPassword(password string) error {
	return u.ValidatePwdStaticHash(StaticHash(password))
}

func (u *User) ValidatePwdStaticHash(pwdStaticHash string) error {
	if pwdStaticHash == "" {
		return errors.WithStack(errs.EmptyPassword)
	}
	if u.PwdHash != HashPwd(pwdStaticHash, u.Salt) {
		return errors.WithStack(errs.WrongPassword)
	}
	return nil
}

const (
	argon2Time    = 1
	argon2Memory  = 64 * 1024
	argon2Threads = 4
	argon2KeyLen  = 32
)

func Argon2IDHash(password string) string {
	salt := random.String(16)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argon2Memory,
		argon2Time,
		argon2Threads,
		salt,
		base64.RawStdEncoding.EncodeToString(argon2.IDKey([]byte(password), []byte(salt), argon2Time, argon2Memory, argon2Threads, argon2KeyLen)))
}

func (u *User) ValidatePassword(password string) error {
	if strings.HasPrefix(u.PwdHash, "$argon2id$") {
		parts := strings.Split(u.PwdHash, "$")
		if len(parts) != 6 {
			return errors.New("invalid argon2id hash format")
		}
		salt := parts[4]
		hash, err := base64.RawStdEncoding.DecodeString(parts[5])
		if err != nil {
			return err
		}
		newHash := argon2.IDKey([]byte(password), []byte(salt), argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
		if !bytes.Equal(hash, newHash) {
			return errors.WithStack(errs.WrongPassword)
		}
		return nil
	}
	return u.ValidatePwdStaticHash(StaticHash(password))
}

func (u *User) SetPassword(pwd string) *User {
	u.Salt = random.String(16)
	u.PwdHash = Argon2IDHash(pwd)
	u.PwdTS = time.Now().Unix()
	return u
}

func (u *User) CanSeeHides() bool {
	return u.Permission&1 == 1
}

func (u *User) CanAccessWithoutPassword() bool {
	return (u.Permission>>1)&1 == 1
}

func (u *User) CanAddOfflineDownloadTasks() bool {
	return (u.Permission>>2)&1 == 1
}

func (u *User) CanWrite() bool {
	return (u.Permission>>3)&1 == 1
}

func (u *User) CanRename() bool {
	return (u.Permission>>4)&1 == 1
}

func (u *User) CanMove() bool {
	return (u.Permission>>5)&1 == 1
}

func (u *User) CanCopy() bool {
	return (u.Permission>>6)&1 == 1
}

func (u *User) CanRemove() bool {
	return (u.Permission>>7)&1 == 1
}

func (u *User) CanWebdavRead() bool {
	return (u.Permission>>8)&1 == 1
}

func (u *User) CanWebdavManage() bool {
	return (u.Permission>>9)&1 == 1
}

func (u *User) CanFTPAccess() bool {
	return (u.Permission>>10)&1 == 1
}

func (u *User) CanFTPManage() bool {
	return (u.Permission>>11)&1 == 1
}

func (u *User) CanReadArchives() bool {
	return (u.Permission>>12)&1 == 1
}

func (u *User) CanDecompress() bool {
	return (u.Permission>>13)&1 == 1
}

func (u *User) JoinPath(reqPath string) (string, error) {
	return utils.JoinBasePath(u.BasePath, reqPath)
}

func StaticHash(password string) string {
	return utils.HashData(utils.SHA256, []byte(fmt.Sprintf("%s-%s", password, StaticHashSalt)))
}

func HashPwd(static string, salt string) string {
	return utils.HashData(utils.SHA256, []byte(fmt.Sprintf("%s-%s", static, salt)))
}

func TwoHashPwd(password string, salt string) string {
	return HashPwd(StaticHash(password), salt)
}

func (u *User) WebAuthnID() []byte {
	bs := make([]byte, 8)
	binary.LittleEndian.PutUint64(bs, uint64(u.ID))
	return bs
}

func (u *User) WebAuthnName() string {
	return u.Username
}

func (u *User) WebAuthnDisplayName() string {
	return u.Username
}

func (u *User) WebAuthnCredentials() []webauthn.Credential {
	var res []webauthn.Credential
	err := json.Unmarshal([]byte(u.Authn), &res)
	if err != nil {
		fmt.Println(err)
	}
	return res
}

func (u *User) WebAuthnIcon() string {
	return "https://cdn.oplist.org/gh/OpenListTeam/Logo@main/OpenList.svg"
}
