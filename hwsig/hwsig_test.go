package hwsig

import (
	"fmt"
	"sort"
	"testing"
)

func TestCalc(t *testing.T) {
	fmt.Println(CalcAll())
}

func TestWinXxx(t *testing.T) {
	keys := []int{}
	for k := range componentMap {
		keys = append(keys, int(k))
	}

	sort.Ints(keys)
	fmt.Printf("#%v\n", keys)

	for _, key := range keys {
		if component, ok := componentMap[Component(key)]; !ok {
			fmt.Println("Could not find: ", key)
		} else {
			s, err := component()
			fmt.Printf("Component %s: %#v\n", s, err)
			Calc([]Component{Component(key)})
		}
	}
}
