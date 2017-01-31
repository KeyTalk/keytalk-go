package rccd

import "testing"

func TestXxx(t *testing.T) {
	v, err := Open("test.rccd")
	if err != nil {
		t.Fatal("Error: %s", err.Error())
	}
	_ = v
}
