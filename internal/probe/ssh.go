package probe

import "strings"

// SSHInfo est la version annoncée par un serveur SSH.
type SSHInfo struct {
	Protocol string `json:"protocol"`          // 2.0 (ou 1.99 : SSHv1 encore accepté)
	Software string `json:"software"`          // OpenSSH_8.9p1
	Comment  string `json:"comment,omitempty"` // Ubuntu-3ubuntu0.4
	Product  string `json:"product,omitempty"` // OpenSSH
	Version  string `json:"version,omitempty"` // 8.9p1
}

// ParseSSHBanner lit « SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4 ».
func ParseSSHBanner(line string) *SSHInfo {
	line = strings.TrimSpace(line)
	rest, ok := strings.CutPrefix(line, "SSH-")
	if !ok {
		return nil
	}
	info := &SSHInfo{}
	info.Protocol, rest, _ = strings.Cut(rest, "-")
	info.Software, info.Comment, _ = strings.Cut(rest, " ")
	sep := strings.IndexAny(info.Software, "_-")
	if sep > 0 {
		info.Product, info.Version = info.Software[:sep], info.Software[sep+1:]
	} else {
		info.Product = info.Software
	}
	return info
}
