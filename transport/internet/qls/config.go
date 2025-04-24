package qls

import (
	"github.com/xtls/xray-core/transport/internet"
)

func ConfigFromStreamSettings(settings *internet.MemoryStreamConfig) *Config {
	if settings == nil || settings.SecuritySettings == nil {
		return nil
	}
	qlsConfigProto, ok := settings.SecuritySettings.(*Config)
	if !ok {
		return nil
	}
	return &Config{
		PublicKey:        qlsConfigProto.PublicKey,
		PrivateKey:       qlsConfigProto.PrivateKey,
		HandshakeTimeout: qlsConfigProto.HandshakeTimeout,
	}
}
