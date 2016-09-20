# Keytalk SDK for Go
[![GoDoc](https://godoc.org/github.com/KeyTalk/Go?status.svg)](http://godoc.org/github.com/KeyTalk/Go) [![Build Status](https://travis-ci.org/KeyTalk/Go.svg?branch=master)](https://travis-ci.org/KeyTalk/Go)


# Install

```
$ go get -u github.com/minio/minio-go
```

# Sample

```
rccd = rccd.Load("test.rccd")

kc, err := keytalk.New(rccd, fmt.Sprintf("https://%s", provider))
if err != nil {
        panic (err)
}

username = r.PostFormValue("username")
password = r.PostFormValue("password")
if uc, err := kc.Authenticate(username, password, rt.service.Name); err != nil {
        panic (err)
} else {
        // got certificate here
}
```
