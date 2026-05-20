"""
tools/adapters — Thin tool dispatch layer.

Each adapter:
  1. Accepts (target, options) → calls raw tool
  2. Returns standardised ToolResult dict
  3. NO state mutation, NO observation extraction, NO entity creation
"""
from tools.adapters.dispatcher import dispatch_tool, ToolResult

__all__ = ["dispatch_tool", "ToolResult"]
