package golang

import (
	"encoding/json"
	"fmt"

	"github.com/robertkrimen/otto"
)

func JSGoLog(jsVM *otto.Otto, logFunc func(args ...any)) func(otto.FunctionCall) otto.Value {
	return func(call otto.FunctionCall) otto.Value {
		if len(call.ArgumentList) == 0 {
			return otto.NullValue()
		}
		args := make([]any, 0, len(call.ArgumentList))
		for _, arg := range call.ArgumentList {
			args = append(args, fmt.Sprint(logValue(arg)))
		}
		logFunc(args...)
		return otto.NullValue()
	}
}

func logValue(v otto.Value) any {
	raw, err := v.MarshalJSON()
	if err != nil {
		return "???"
	}
	var m any
	err = json.Unmarshal(raw, &m)
	if err != nil {
		return "???"
	}
	return m
}
