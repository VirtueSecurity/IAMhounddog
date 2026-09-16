package graph

import "slices"

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
	Graph Graph          `json:"graph"`
	index map[string]int `json:"-"`
}

func AddNode(out *Output, id string, kinds []string, props map[string]interface{}) bool {
	if out.index == nil {
		out.index = make(map[string]int)
	}

	if i, seen := out.index[id]; seen {
		mergeNode(&out.Graph.Nodes[i], kinds, props)
		return false
	}

	out.Graph.Nodes = append(out.Graph.Nodes, Node{
		ID:         id,
		Kinds:      kinds,
		Properties: props,
	})
	out.index[id] = len(out.Graph.Nodes) - 1
	return true
}

func mergeNode(n *Node, kinds []string, props map[string]interface{}) {
	for _, k := range kinds {
		if !slices.Contains(n.Kinds, k) {
			n.Kinds = append(n.Kinds, k)
		}
	}

	if len(props) == 0 {
		return
	}

	if n.Properties == nil {
		n.Properties = make(map[string]interface{}, len(props))
	}

	for k, v := range props {
		if existing, ok := n.Properties[k]; ok && existing != nil && existing != "" {
			continue
		}
		n.Properties[k] = v
	}
}

func HasAnyKind(out *Output, id string, kinds ...string) bool {
	i, seen := out.index[id]
	if !seen {
		return false
	}

	for _, want := range kinds {
		if slices.Contains(out.Graph.Nodes[i].Kinds, want) {
			return true
		}
	}

	return false
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
