import importlib.util
import os
import sys
import types
from pathlib import Path


def _load_case_module():
    os.environ['DATA_ENCRYPTION_KEY'] = '9pc95JNaPykspfJ-GFBzf8d3crUxVLUehbhyGv3lE1Y='
    # Unit test only: stub asyncpg so the module can be imported without DB dependency.
    if 'asyncpg' not in sys.modules:
        asyncpg_stub = types.SimpleNamespace(Pool=object, create_pool=None)
        sys.modules['asyncpg'] = asyncpg_stub
    if 'aiokafka' not in sys.modules:
        aiokafka_stub = types.SimpleNamespace(AIOKafkaProducer=object)
        sys.modules['aiokafka'] = aiokafka_stub
    if 'prometheus_fastapi_instrumentator' not in sys.modules:
        class _Instr:
            def instrument(self, app):
                return self
            def expose(self, app):
                return self
        sys.modules['prometheus_fastapi_instrumentator'] = types.SimpleNamespace(Instrumentator=_Instr)
    path = Path('services/case-service/app/main.py')
    spec = importlib.util.spec_from_file_location('case_main', path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_encrypt_decrypt_round_trip():
    m = _load_case_module()
    raw = {
        'description': 'sensitive case narrative',
        'comments': [{'text': 'secret note'}],
    }
    enc = m._encrypt_case_payload(raw)
    assert enc['description'] != raw['description']
    assert enc['comments'][0]['text'] != raw['comments'][0]['text']

    dec = m._decrypt_case_payload(enc)
    assert dec['description'] == raw['description']
    assert dec['comments'][0]['text'] == raw['comments'][0]['text']
