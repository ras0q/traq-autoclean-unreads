package filter

import (
	"context"
	"fmt"
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
	"github.com/traPtitech/go-traq"
)

type CELInput struct {
	Channel          traq.UnreadChannel
	Messages         []traq.Message
	PublicChannelMap map[string]traq.Channel
	UserMap          map[string]traq.User
}

var CELEnv, _ = cel.NewEnv(
	cel.Variable("input", cel.ObjectType("filter.CELInput")),
	ext.NativeTypes(
		reflect.TypeFor[CELInput](),
		reflect.TypeFor[traq.Message](),
		reflect.TypeFor[traq.User](),
	),
)

const DefaultCELFilter string = `input.Channel.Count > 0
&& !input.Channel.Noticeable
&& input.Channel.ChannelId in input.PublicChannelMap
&& input.Messages.all(m, input.UserMap[m.UserId].Bot)`

func EvaluateCEL(ctx context.Context, celProgram string, input CELInput) (bool, error) {
	ast, iss := CELEnv.Compile(celProgram)
	if err := iss.Err(); err != nil {
		return false, err
	}

	prg, err := CELEnv.Program(ast)
	if err != nil {
		return false, err
	}

	output, _, err := prg.ContextEval(ctx, map[string]any{"input": input})
	if err != nil {
		return false, err
	}

	outputBool, ok := output.Value().(bool)
	if !ok {
		return false, fmt.Errorf("output of the program must be a boolean type")
	}

	return outputBool, nil
}
