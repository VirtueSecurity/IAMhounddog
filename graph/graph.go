package graph

type Node struct {
	ID         string                 `json:"id"`
	Kinds      []string               `json:"kinds"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type Edge struct {
	Kind  string `json:"kind"`
	Start struct {
		Value string `json:"value"`
	} `json:"start"`
	End struct {
		Value string `json:"value"`
	} `json:"end"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

type Output struct {
	Graph Graph `json:"graph"`
}

func AddNode(out *Output, id string, kinds []string, props map[string]interface{}) {
	out.Graph.Nodes = append(out.Graph.Nodes, Node{
		ID:         id,
		Kinds:      kinds,
		Properties: props,
	})
}

func AddNodeOnce(out *Output, set map[string]bool, id string, kinds []string, props map[string]interface{}) {
	if set[id] {
		return
	}

	AddNode(out, id, kinds, props)

	set[id] = true
}

func AddEdge(out *Output, kind, start, end string, props map[string]interface{}) {
	out.Graph.Edges = append(out.Graph.Edges, Edge{
		Kind: kind,
		Start: struct {
			Value string `json:"value"`
		}{
			Value: start,
		},
		End: struct {
			Value string `json:"value"`
		}{
			Value: end,
		},
		Properties: props,
	})
}
