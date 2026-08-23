import ast
from pathlib import Path


def test_member_route_regex_does_not_depend_on_handle_post_local_re_binding():
    source = (Path(__file__).parents[1] / "api/routes.py").read_text()
    tree = ast.parse(source)
    handle_post = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "handle_post")
    loads = []
    bindings = []
    for node in ast.walk(handle_post):
        if isinstance(node, ast.Name) and node.id == "_re":
            if isinstance(node.ctx, ast.Load):
                loads.append(node.lineno)
            else:
                bindings.append(node.lineno)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname == "_re":
                    bindings.append(node.lineno)
    assert loads
    assert min(loads) > min(bindings)
    assert "_ROUTE_RE.fullmatch(r\"/api/member/rooms/([^/]+)/messages\"" in source
