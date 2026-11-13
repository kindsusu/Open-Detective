"""JSON decoding that never silently discards duplicate exposure fields."""
import json
import math


def _constant(_token):
    raise ValueError("nonfinite_json")


def _float(token):
    value = float(token)
    if not math.isfinite(value):
        raise ValueError("nonfinite_json")
    return value


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def loads(data):
    return json.loads(data, parse_constant=_constant, parse_float=_float,
                      object_pairs_hook=_object)
