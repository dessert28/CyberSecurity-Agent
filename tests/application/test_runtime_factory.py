from __future__ import annotations

import pytest

from cyber_agent.application.run_management import RunManagementError
from cyber_agent.application.runtime_factory import RealRuntimeFactory
from cyber_agent.contracts.model import ModelHealth


class _UnavailableModel:
    async def health_check(self) -> ModelHealth:
        return ModelHealth(
            available=False,
            provider="test-provider",
            model="test-model",
            message="endpoint refused the connection",
        )


@pytest.mark.asyncio
async def test_model_health_gate_rejects_unavailable_endpoint() -> None:
    with pytest.raises(RunManagementError) as caught:
        await RealRuntimeFactory._ensure_model_available(_UnavailableModel())

    assert caught.value.code == "MODEL_ENDPOINT_UNAVAILABLE"
    assert caught.value.status_code == 503
