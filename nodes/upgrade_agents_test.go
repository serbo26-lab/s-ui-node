package nodes

import (
	"testing"

	"github.com/alireza0/s-ui/nodeagent"
)

func TestAgentUpgradeRequiresRunningIdentityAndMatchingAccess(t *testing.T) {
	before := nodeagent.StatusV2{NodeID: 1, Epoch: "epoch", SpecRevision: 2, SpecDigest: "spec", AccessRevision: 3, AccessDigest: "access"}
	after := before
	after.SingBoxVersion, after.AgentDigest, after.Running = "v1.14.4", "new-artifact", true
	after.AppliedAccessRevision, after.AppliedAccessDigest = 3, "access"
	if !matchesAgentUpgrade(before, after, "v1.14.4", "new-artifact") {
		t.Fatal("compatible update rejected")
	}
	for _, change := range []func(*nodeagent.StatusV2){
		func(s *nodeagent.StatusV2) { s.Running = false },
		func(s *nodeagent.StatusV2) { s.Epoch = "replaced" },
		func(s *nodeagent.StatusV2) { s.SpecDigest = "lost" },
		func(s *nodeagent.StatusV2) { s.AppliedAccessRevision-- },
		func(s *nodeagent.StatusV2) { s.AgentDigest = "old-artifact" },
	} {
		bad := after
		change(&bad)
		if matchesAgentUpgrade(before, bad, "v1.14.4", "new-artifact") {
			t.Fatalf("accepted incompatible state: %+v", bad)
		}
	}
}
