from pathlib import Path
from typing import Union
import json


def load_contract(path: Union[str, Path]) -> dict:
    contract_path = Path(path)

    with contract_path.open("r", encoding="utf-8") as f:
        return json.load(f)
