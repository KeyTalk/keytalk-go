package rccd

type SourceV1 struct {
	checksum string
	source   string
}

func (i *SourceV1) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var m map[string]interface{}
	if err := unmarshal(&m); err != nil {
		return err
	}

	if v, ok := m["Checksum"]; !ok {
	} else if v, ok := v.(string); !ok {
	} else {
		i.checksum = v
	}

	if v, ok := m["Source"]; !ok {
	} else if v, ok := v.(string); !ok {
	} else {
		i.source = v
	}

	return nil
}

func (i *IndexV1) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var m struct {
		ContentVersion string   `yaml:"ContentVersion"`
		Logo           SourceV1 `yaml:"Logo"`
		UserConfig     SourceV1 `yaml:"UserConfig"`

		UCA SourceV1 `yaml:"UCA"`
		SCA SourceV1 `yaml:"SCA"`
		PCA SourceV1 `yaml:"PCA"`

		SignedSvrCommPubKey SourceV1 `yaml:"SignedSvrCommPubKey"`
	}

	if err := unmarshal(&m); err != nil {
		return err
	}

	i.contentVersion = m.ContentVersion
	i.logo = m.Logo
	i.userConfig = m.UserConfig
	i.uca = m.UCA
	i.sca = m.SCA
	i.pca = m.PCA
	i.signedSvrCommPubKey = m.SignedSvrCommPubKey

	return nil
}

type IndexV1 struct {
	contentVersion string
	logo           SourceV1
	userConfig     SourceV1

	uca SourceV1
	sca SourceV1
	pca SourceV1

	signedSvrCommPubKey SourceV1
}

func (i IndexV1) Logo() string {
	return i.logo.source
}

func (i IndexV1) SCA() string {
	return i.sca.source
}

func (i IndexV1) UCA() string {
	return i.uca.source
}

func (i IndexV1) PCA() string {
	return i.pca.source
}

func (i IndexV1) UserConfig() string {
	return i.userConfig.source
}

func (i IndexV1) ExtraSigningCAs() []string {
	return []string{}
}
