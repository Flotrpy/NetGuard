"""YAML loading that keeps line numbers and tolerates CloudFormation/custom tags."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode


class _Loader(yaml.SafeLoader):
    pass


def _any_tag(loader: yaml.SafeLoader, suffix: str, node: Node) -> Any:  # noqa: ARG001
    if isinstance(node, ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, SequenceNode):
        return loader.construct_sequence(node, deep=True)
    return loader.construct_mapping(node, deep=True)  # type: ignore[arg-type]


_Loader.add_multi_constructor("!", _any_tag)


def load_documents(text: str) -> Iterator[tuple[Any, Node]]:
    """Yield (python object, yaml node) per non-empty document. Raises yaml.YAMLError."""
    loader = _Loader(text)
    try:
        while loader.check_node():
            node = loader.get_node()
            obj = loader.construct_document(node)
            if obj is not None:
                yield obj, node
    finally:
        loader.dispose()


def child(node: Node | None, key: str | int) -> Node | None:
    """Value node for a mapping key / sequence index, or None."""
    if isinstance(node, MappingNode) and isinstance(key, str):
        for k, v in node.value:
            if isinstance(k, ScalarNode) and k.value == key:
                return v
    if isinstance(node, SequenceNode) and isinstance(key, int) and 0 <= key < len(node.value):
        return node.value[key]
    return None


def key_line(node: Node | None, key: str, default: int = 1) -> int:
    """1-based line of ``key`` within a mapping node (falls back to the node's own line)."""
    if isinstance(node, MappingNode):
        for k, _ in node.value:
            if isinstance(k, ScalarNode) and k.value == key:
                return k.start_mark.line + 1
        return node.start_mark.line + 1
    return node.start_mark.line + 1 if node is not None else default


def node_line(node: Node | None, default: int = 1) -> int:
    return node.start_mark.line + 1 if node is not None else default


def walk(node: Node | None, *path: str | int) -> Node | None:
    for p in path:
        node = child(node, p)
        if node is None:
            return None
    return node
