package config

import (
    "gopkg.in/ini.v1"
)

type Config struct {
    SSHPort     string
    HostKeyFile string
    ForceCommand string
    NickServAPI struct {
        URL   string
        Token string
    }
}

func Load(path string) (*Config, error) {
    cfgFile, err := ini.Load(path)
    if err != nil {
        return nil, err
    }

    cfg := &Config{}

    serverSection := cfgFile.Section("server")
    cfg.SSHPort = serverSection.Key("port").MustString("2222")
    cfg.HostKeyFile = serverSection.Key("host_key_file").String()
    cfg.ForceCommand = serverSection.Key("force_command").String()

    nickservSection := cfgFile.Section("nickserv")
    cfg.NickServAPI.URL = nickservSection.Key("api_url").String()
    cfg.NickServAPI.Token = nickservSection.Key("api_token").String()

    return cfg, nil
}
