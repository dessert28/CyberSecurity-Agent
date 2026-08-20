"""Tool plugin implementation boundary."""

from .policy import BudgetUsage, PolicyGate, SocketResolver, StaticResolver
from .hypothesis_validate import (
    HYPOTHESIS_VALIDATE_CAPABILITY,
    HYPOTHESIS_VALIDATE_TOOL_ID,
    HypothesisValidatePlugin,
    HypothesisValidationHandler,
    HypothesisValidationResult,
)
from .project_inventory import (
    PROJECT_INVENTORY_CAPABILITY,
    PROJECT_INVENTORY_TOOL_ID,
    ProjectInventoryAnalyzer,
    ProjectInventoryError,
    ProjectInventoryPlugin,
    ProjectInventoryResult,
)
from .python_dataflow import (
    PYTHON_DATAFLOW_CAPABILITY,
    PYTHON_DATAFLOW_TOOL_ID,
    DataflowAnalysisResult,
    DataflowHypothesis,
    PythonDataflowAnalyzer,
    PythonDataflowError,
    PythonDataflowPlugin,
)
from .registry import HealthState, RegistryError, RegistryStatus, ToolRegistry
from .validation import ArgumentValidationError, validate_arguments
from .web import (
    EndpointDiscoveryPlugin,
    HttpRequestPlugin,
    OpenApiAnalyzePlugin,
    built_in_web_plugins,
)

__all__ = [
    "ArgumentValidationError",
    "BudgetUsage",
    "EndpointDiscoveryPlugin",
    "HealthState",
    "HttpRequestPlugin",
    "HYPOTHESIS_VALIDATE_CAPABILITY",
    "HYPOTHESIS_VALIDATE_TOOL_ID",
    "HypothesisValidatePlugin",
    "HypothesisValidationHandler",
    "HypothesisValidationResult",
    "OpenApiAnalyzePlugin",
    "PYTHON_DATAFLOW_CAPABILITY",
    "PYTHON_DATAFLOW_TOOL_ID",
    "PROJECT_INVENTORY_CAPABILITY",
    "PROJECT_INVENTORY_TOOL_ID",
    "PolicyGate",
    "DataflowAnalysisResult",
    "DataflowHypothesis",
    "ProjectInventoryAnalyzer",
    "ProjectInventoryError",
    "ProjectInventoryPlugin",
    "ProjectInventoryResult",
    "PythonDataflowAnalyzer",
    "PythonDataflowError",
    "PythonDataflowPlugin",
    "RegistryError",
    "RegistryStatus",
    "SocketResolver",
    "StaticResolver",
    "ToolRegistry",
    "built_in_web_plugins",
    "validate_arguments",
]
