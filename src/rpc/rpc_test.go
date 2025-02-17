package rpc

import (
	"github.com/3t2ugg1e/go-engine/src/common"
	"github.com/3t2ugg1e/go-engine/src/loggo"
	"testing"
)

func Test0001(t *testing.T) {

	call := NewCall(1000)
	_, err := call.Call(func() {
		loggo.Info("start call %s", call.Id())
	})
	loggo.Info("call ret %s", err)
}

func Test0002(t *testing.T) {

	call := NewCall(1000)
	ret, _ := call.Call(func() {
		loggo.Info("start call %s", call.Id())
		go func() {
			defer common.CrashLog()
			PutRet(call.Id(), 1, 2, "a")
		}()
	})
	loggo.Info("call ret %v", ret)
}
