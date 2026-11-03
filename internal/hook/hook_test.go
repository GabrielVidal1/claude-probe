package hook

import (
	"strings"
	"testing"
)

func TestEventMapping(t *testing.T) {
	pre := Event(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Bash",
		"session_id": "s", "tool_use_id": "toolu_1", "prompt_id": "p", "agent_id": "a1",
		"agent_type": "Explore", "tool_input": map[string]any{"command": "ls", "run_in_background": true}})
	if pre == nil || pre.E != "pre" || pre.Tid != "toolu_1" || !pre.Bg || pre.AgentType != "Explore" || len(pre.Chain) == 0 {
		t.Fatal(pre)
	}
	post := Event(map[string]any{"hook_event_name": "PostToolUse", "tool_name": "Bash",
		"tool_use_id": "toolu_1", "duration_ms": 12.0, "tool_input": map[string]any{"command": "rtk ls"},
		"tool_response": map[string]any{"backgroundTaskId": "b1"}})
	if post.DurationMs == nil || *post.DurationMs != 12 || post.BgTask != "b1" || post.Chain != nil {
		t.Fatal(post)
	}
	if Event(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Read"}) != nil {
		t.Fatal("a Read call is not ours")
	}
	stop := Event(map[string]any{"hook_event_name": "Stop", "background_tasks": []any{1, 2}})
	if stop.E != "stop" || *stop.BgTasks != 2 {
		t.Fatal(stop)
	}
	if Event(map[string]any{"hook_event_name": "Notification"}) != nil {
		t.Fatal("Notification is not ours")
	}
}

func TestNoDaemonPrintsNothingAndReturns(t *testing.T) {
	t.Setenv("CLAUDE_PROBE_SOCK", t.TempDir()+"/none.sock")
	t.Setenv("CLAUDE_PROBE_NO_SPAWN", "1")
	Run(strings.NewReader(`{"hook_event_name":"UserPromptSubmit","session_id":"s"}`), "/nonexistent")
}
