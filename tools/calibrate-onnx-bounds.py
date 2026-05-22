#!/usr/bin/env python3
"""calibrate-onnx-bounds.py — report the minimum `OnnxHostBounds` an
application must declare to admit a given ONNX `ModelProto`.

Operational helper. Walks the model (recursing into subgraphs) and
prints per-constant maxima plus a paste-ready `impl OnnxHostBounds`.

Usage:
    python3 calibrate-onnx-bounds.py MODEL.onnx
"""
import sys

# Reuse the inlined protobuf reader from canonical-onnx.py.
import importlib.util
import os

_spec = importlib.util.spec_from_file_location(
    "canonical_onnx", os.path.join(os.path.dirname(__file__), "canonical-onnx.py"))
_co = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_co)
each, first_bytes, first_varint = _co.each, _co.first_bytes, _co.first_varint


def walk_graph(graph, depth, o):
    o["subgraph_depth"] = max(o["subgraph_depth"], depth)
    nodes = list(each(graph, 1))
    o["nodes"] = max(o["nodes"], len(nodes))
    o["initializers"] = max(o["initializers"], len(list(each(graph, 5))))
    for n in nodes:
        o["node_inputs"] = max(o["node_inputs"], len(list(each(n, 1))))
        o["node_outputs"] = max(o["node_outputs"], len(list(each(n, 2))))
        attrs = list(each(n, 5))
        o["node_attrs"] = max(o["node_attrs"], len(attrs))
        for a in attrs:
            atype = first_varint(a, 20)
            if atype == 5:
                walk_graph(first_bytes(a, 6), depth + 1, o)
            elif atype == 10:
                for g in each(a, 11):
                    walk_graph(g, depth + 1, o)


def calibrate(model):
    o = {"nodes": 0, "initializers": 0, "node_inputs": 0, "node_outputs": 0,
         "node_attrs": 0, "subgraph_depth": 0, "opset_imports": 0,
         "opset_min": 0, "model_bytes": len(model)}
    o["opset_imports"] = len(list(each(model, 8)))
    o["opset_min"] = min((first_varint(e, 2) for e in each(model, 8)
                          if not first_bytes(e, 1)), default=1)
    walk_graph(first_bytes(model, 7), 0, o)
    return o


def main(argv):
    if len(argv) != 2:
        print(__doc__, file=sys.stderr); return 2
    o = calibrate(open(argv[1], "rb").read())
    print(f"ONNX_GRAPH_NODE_COUNT_MAX     >= {o['nodes']}")
    print(f"ONNX_INITIALIZER_COUNT_MAX    >= {o['initializers']}")
    print(f"ONNX_NODE_INPUT_COUNT_MAX     >= {o['node_inputs']}")
    print(f"ONNX_NODE_OUTPUT_COUNT_MAX    >= {o['node_outputs']}")
    print(f"ONNX_NODE_ATTRIBUTE_COUNT_MAX >= {o['node_attrs']}")
    print(f"ONNX_SUBGRAPH_DEPTH_MAX       >= {o['subgraph_depth']}")
    print(f"ONNX_OPSET_IMPORT_COUNT_MAX   >= {o['opset_imports']}")
    print(f"ONNX_MODEL_BYTES_MAX          >= {o['model_bytes']}")
    print(f"ONNX_OPSET_VERSION_MIN        <= {o['opset_min']} (default-domain opset)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
