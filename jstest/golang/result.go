package golang

import "github.com/robertkrimen/otto"

func JSDo[T any](jsVM *otto.Otto, f func(call otto.FunctionCall) (*T, error)) func(call otto.FunctionCall) otto.Value {
	return func(call otto.FunctionCall) otto.Value {
		result, err := f(call)
		obj, _ := jsVM.Object(`({})`)
		if err != nil {
			obj.Set("error", err.Error())
		} else {
			obj.Set("value", *result)
		}
		return obj.Value()
	}
}
