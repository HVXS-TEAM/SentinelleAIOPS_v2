"""Configuration Pytest pour Sentinelle AIOps v2.

Fournit le support natif des fonctions de test asynchrones (@pytest.mark.asyncio)
via la bibliothèque standard asyncio lorsque pytest-asyncio n'est pas installé.
"""
import asyncio
import inspect
import pytest


def pytest_configure(config: pytest.Config) -> None:
    """Déclare le marqueur asyncio pour éviter tout avertissement PytestUnknownMarkWarning."""
    config.addinivalue_line("markers", "asyncio: exécute un test asynchrone via asyncio.run()")


@pytest.hookimpl(tryfirst=True)
def pytest_pyfunc_call(pyfuncitem: pytest.Function) -> bool | None:
    """Exécute les coroutines de test dans une boucle d'événements asyncio isolée."""
    testfunction = pyfuncitem.obj
    if inspect.iscoroutinefunction(testfunction):
        funcargs = pyfuncitem.funcargs
        testargs = {arg: funcargs[arg] for arg in pyfuncitem._fixtureinfo.argnames}
        asyncio.run(testfunction(**testargs))
        return True
    return None

