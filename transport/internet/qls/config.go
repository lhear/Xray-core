package qls

import (
	"github.com/xtls/xray-core/transport/internet"
)

func ConfigFromStreamSettings(settings *internet.MemoryStreamConfig) *Config {
	if settings == nil || settings.SecuritySettings == nil {
		return nil // 没有流设置或安全设置
	}
	// 检查 SecuritySettings 是否是 QLS 的 protobuf 配置类型
	qlsConfigProto, ok := settings.SecuritySettings.(*Config)
	if !ok {
		return nil // 不是 QLS 配置
	}
	return &Config{
		PublicKey:        qlsConfigProto.PublicKey,
		PrivateKey:       qlsConfigProto.PrivateKey,
		HandshakeTimeout: qlsConfigProto.HandshakeTimeout,
	}
}
