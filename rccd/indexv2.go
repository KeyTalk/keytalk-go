package rccd

type IndexV2 struct {
	version    string
	logo       string
	userConfig string

	uca string
	sca string
	pca string

	extraSigningCAs []string

	clntSvrCommCert string
}

func (i *IndexV2) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var m map[string]interface{}
	if err := unmarshal(&m); err != nil {
		return err
	}

	if v, ok := m["ConfigVersion"]; !ok {
	} else if v, ok := v.(string); !ok {
	} else {
		i.version = v
	}

	if v, ok := m["Logo"]; !ok {
	} else if v, ok := v.(string); !ok {
	} else {
		i.logo = v
	}

	if v, ok := m["UserConfig"]; !ok {
	} else if v, ok := v.(string); !ok {
	} else {
		i.userConfig = v
	}

	if v, ok := m["UCA"]; !ok {
	} else if v, ok := v.(string); !ok {
	} else {
		i.uca = v
	}

	if v, ok := m["SCA"]; !ok {
	} else if v, ok := v.(string); !ok {
	} else {
		i.sca = v
	}

	if v, ok := m["PCA"]; !ok {
	} else if v, ok := v.(string); !ok {
	} else {
		i.pca = v
	}

	if v, ok := m["ClntSvrCommCert"]; !ok {
	} else if v, ok := v.(string); !ok {
	} else {
		i.clntSvrCommCert = v
	}

	if v, ok := m["ExtraSigningCAs"]; !ok {
	} else if v, ok := v.([]string); !ok {
	} else {
		i.extraSigningCAs = v
	}

	return nil
}

func (i IndexV2) Logo() string {
	return i.logo
}

func (i IndexV2) SCA() string {
	return i.sca
}

func (i IndexV2) UCA() string {
	return i.uca
}

func (i IndexV2) PCA() string {
	return i.pca
}

func (i IndexV2) ExtraSigningCAs() []string {
	return i.extraSigningCAs
}

func (i IndexV2) UserConfig() string {
	return i.userConfig
}
