package proxy

import "context"

type DenyPrompter struct{}

func (DenyPrompter) Ask(_ context.Context, _ string, _ int) (Answer, error) {
	return AnswerDeny, nil
}
