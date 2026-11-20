package nodeagent

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CertificateStatus describes public certificate material, never a private key,
// provider credentials, raw parser errors or arbitrary filesystem paths.
// Source is storage/config inspection, not an external handshake probe.
type CertificateStatus struct {
	Inbound    string `json:"inbound"`
	Provider   string `json:"provider,omitempty"`
	ServerName string `json:"server_name,omitempty"`
	State      string `json:"state"`
	NotBefore  int64  `json:"not_before,omitempty"`
	NotAfter   int64  `json:"not_after,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
}

// ValidateCertificateReferences also runs on the panel before network I/O.
func ValidateCertificateReferences(config []byte) error {
	var value struct {
		Providers []struct {
			Type    string   `json:"type"`
			Tag     string   `json:"tag"`
			Domains []string `json:"domain"`
		} `json:"certificate_providers"`
		Inbounds []struct {
			Type      string `json:"type"`
			Transport struct {
				Type string `json:"type"`
			} `json:"transport"`
			TLS struct {
				Enabled  bool   `json:"enabled"`
				Provider string `json:"certificate_provider"`
				Reality  struct {
					Enabled bool `json:"enabled"`
				} `json:"reality"`
			} `json:"tls"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(config, &value); err != nil {
		return err
	}
	providers := map[string]bool{}
	for _, p := range value.Providers {
		if strings.TrimSpace(p.Tag) == "" || providers[p.Tag] {
			return errors.New("certificate provider tags must be nonempty and unique")
		}
		if p.Type != "acme" && p.Type != "cloudflare-origin-ca" {
			return errors.New("node certificate provider type is not supported")
		}
		if len(p.Domains) == 0 {
			return errors.New("certificate provider needs at least one domain")
		}
		providers[p.Tag] = true
	}
	for _, i := range value.Inbounds {
		if RequiresRegularTLS(i.Type, i.Transport.Type) && (!i.TLS.Enabled || i.TLS.Reality.Enabled) {
			return errors.New("this node inbound needs regular TLS")
		}
		if i.TLS.Enabled && i.TLS.Provider != "" && !providers[i.TLS.Provider] {
			return errors.New("TLS references an unknown node certificate provider")
		}
	}
	return nil
}

func (r *CoreRuntime) prepareCertificates(config []byte, create bool) ([]byte, error) {
	if err := ValidateCertificateReferences(config); err != nil {
		return nil, err
	}
	var value map[string]interface{}
	if err := json.Unmarshal(config, &value); err != nil {
		return nil, err
	}
	providers, _ := value["certificate_providers"].([]interface{})
	if inbounds, ok := value["inbounds"].([]interface{}); ok {
		for _, item := range inbounds {
			inbound, _ := item.(map[string]interface{})
			settings, _ := inbound["tls"].(map[string]interface{})
			cert, _ := settings["certificate_path"].(string)
			key, _ := settings["key_path"].(string)
			if strings.HasPrefix(cert, "managed:") || strings.HasPrefix(key, "managed:") {
				if cert != "managed:primary" || key != "managed:primary" || r.certificateResolver == nil {
					return nil, errors.New("managed_certificate_binding_invalid")
				}
				name, _ := settings["server_name"].(string)
				meta, err := r.certificateResolver(name)
				if err != nil {
					return nil, err
				}
				settings["certificate_path"] = filepath.Join(r.stateDirectory, filepath.FromSlash(meta.CertificatePath))
				settings["key_path"] = filepath.Join(r.stateDirectory, filepath.FromSlash(meta.KeyPath))
			}
		}
	}
	used := map[string]bool{}
	for _, item := range providers {
		p := item.(map[string]interface{})
		if r.stateDirectory == "" {
			return nil, errors.New("node certificate providers require a persistent state directory")
		}
		name, _ := p["data_directory"].(string)
		if name == "" {
			sum := sha256.Sum256([]byte(p["type"].(string) + "/" + p["tag"].(string)))
			name = hex.EncodeToString(sum[:12])
		}
		if filepath.IsAbs(name) || strings.HasPrefix(name, "/") || filepath.VolumeName(name) != "" || strings.ContainsAny(name, "$\\:") {
			return nil, errors.New("provider data directory must be relative to node certificate storage")
		}
		clean := filepath.Clean(name)
		if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return nil, errors.New("invalid provider data directory")
		}
		path := filepath.Join(r.stateDirectory, "certificates", clean)
		for previous := range used {
			one, _ := filepath.Rel(previous, path)
			two, _ := filepath.Rel(path, previous)
			inside := func(relative string) bool {
				return relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
			}
			if inside(one) || inside(two) {
				return nil, errors.New("certificate provider data directories must not overlap")
			}
		}
		used[path] = true
		if create {
			if err := privateDirectory(r.stateDirectory, filepath.Join("certificates", clean)); err != nil {
				return nil, err
			}
		}
		p["data_directory"] = path
	}
	// Relative server certificate/key paths belong to this node's state, never
	// to the panel's filesystem or the process working directory.
	if r.stateDirectory != "" {
		var resolve func(interface{})
		resolve = func(v interface{}) {
			switch x := v.(type) {
			case map[string]interface{}:
				for key, item := range x {
					if key == "certificate_path" || key == "key_path" || key == "client_certificate_path" {
						switch p := item.(type) {
						case string:
							if p != "" && !filepath.IsAbs(p) {
								x[key] = filepath.Join(r.stateDirectory, p)
							}
						case []interface{}:
							for j, item := range p {
								if name, ok := item.(string); ok && name != "" && !filepath.IsAbs(name) {
									p[j] = filepath.Join(r.stateDirectory, name)
								}
							}
						}
					} else {
						resolve(item)
					}
				}
			case []interface{}:
				for _, item := range x {
					resolve(item)
				}
			}
		}
		resolve(value["inbounds"])
	}
	return json.Marshal(value)
}

func privateDirectory(root, relative string) error {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	current := root
	for _, part := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		if err := os.Mkdir(current, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("certificate storage must not contain symlinks")
		}
		if err := os.Chmod(current, 0o700); err != nil {
			return err
		}
	}
	return nil
}

func certificateFromPEM(body []byte) *x509.Certificate {
	block, _ := pem.Decode(body)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil
	}
	cert, _ := x509.ParseCertificate(block.Bytes)
	return cert
}

func (r *CoreRuntime) Certificates() []CertificateStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := []CertificateStatus{}
	var config struct {
		Providers []struct {
			Tag       string   `json:"tag"`
			Directory string   `json:"data_directory"`
			Domains   []string `json:"domain"`
		} `json:"certificate_providers"`
		Inbounds []struct {
			Tag string `json:"tag"`
			TLS struct {
				Enabled     bool     `json:"enabled"`
				ServerName  string   `json:"server_name"`
				Provider    string   `json:"certificate_provider"`
				Certificate []string `json:"certificate"`
				Path        string   `json:"certificate_path"`
				Reality     struct {
					Enabled bool `json:"enabled"`
				} `json:"reality"`
			} `json:"tls"`
		} `json:"inbounds"`
	}
	if json.Unmarshal(r.config, &config) != nil {
		return result
	}
	for _, i := range config.Inbounds {
		if !i.TLS.Enabled || i.TLS.Reality.Enabled {
			continue
		}
		status := CertificateStatus{Inbound: i.Tag, Provider: i.TLS.Provider, ServerName: i.TLS.ServerName, State: "missing"}
		var cert *x509.Certificate
		if i.TLS.Provider != "" {
			for _, p := range config.Providers {
				if p.Tag != i.TLS.Provider {
					continue
				}
				if status.ServerName == "" && len(p.Domains) == 1 {
					status.ServerName = p.Domains[0]
				}
				count := 0
				_ = filepath.WalkDir(p.Directory, func(path string, entry fs.DirEntry, err error) error {
					if err != nil {
						return nil
					}
					if entry.Type()&os.ModeSymlink != 0 {
						return filepath.SkipDir
					}
					if entry.IsDir() {
						return nil
					}
					if !strings.HasSuffix(entry.Name(), ".crt") && !strings.HasSuffix(entry.Name(), ".pem") {
						return nil
					}
					count++
					if count > 256 {
						return fs.SkipAll
					}
					info, e := entry.Info()
					if e != nil || info.Size() > 1<<20 {
						return nil
					}
					body, e := os.ReadFile(path)
					if e != nil {
						return nil
					}
					candidate := certificateFromPEM(body)
					if candidate == nil || candidate.IsCA {
						return nil
					}
					if status.ServerName != "" && candidate.VerifyHostname(status.ServerName) != nil {
						return nil
					}
					if cert == nil || candidate.NotAfter.After(cert.NotAfter) {
						cert = candidate
					}
					return nil
				})
			}
		} else if len(i.TLS.Certificate) > 0 {
			cert = certificateFromPEM([]byte(strings.Join(i.TLS.Certificate, "\n")))
		} else if i.TLS.Path != "" {
			if body, err := os.ReadFile(i.TLS.Path); err == nil {
				cert = certificateFromPEM(body)
			}
		}
		if cert != nil {
			status.NotBefore, status.NotAfter = cert.NotBefore.Unix(), cert.NotAfter.Unix()
			sum := sha256.Sum256(cert.Raw)
			status.SHA256 = hex.EncodeToString(sum[:])
			status.State = "ready"
			now := time.Now()
			if now.Before(cert.NotBefore) {
				status.State = "not_yet_valid"
			} else if !now.Before(cert.NotAfter) {
				status.State = "expired"
			} else if status.ServerName != "" && cert.VerifyHostname(status.ServerName) != nil {
				status.State = "name_mismatch"
			}
		}
		result = append(result, status)
	}
	return result
}
