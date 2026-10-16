import re

MAX_FILES = 50
MAX_FILE_BYTES = 256 * 1024
KEY_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_. -]{0,127}$")
PATH_RE = re.compile(r"^[A-Za-z0-9_./-]{1,240}$")
SET_RE = re.compile(r"^SET\s+(.+?)\s*=\s*(.*)$")
NESTED_RE = re.compile(r"^SET_NESTED\s+([A-Za-z0-9_.-]{1,128})\s*:\s*([A-Za-z0-9_.-]{1,128})\s*=\s*(.*)$")
REFERENCE_RE = re.compile(r"^Key:\s*<([A-Za-z0-9_./-]+)\.([A-Za-z0-9_.-]{1,128})>$")

class InstructionError(ValueError):
    pass

def parse_key_reference(value):
    """Return (secret_path, key_name) for a Key: <path.key> value, else None.

    A value beginning with the reserved `Key:` prefix must be a valid reference;
    this avoids silently writing a misspelled reference marker as a literal.
    """
    if not isinstance(value, str) or not value.startswith("Key:"):
        return None
    match = REFERENCE_RE.fullmatch(value.strip())
    if not match:
        raise InstructionError("Invalid key reference. Use: Key: <secret_name.key_name>.")
    secret_path, key_name = match.groups()
    validate_secret_path(secret_path)
    if not KEY_RE.fullmatch(key_name):
        raise InstructionError("Invalid key name in key reference.")
    return secret_path, key_name

def validate_secret_path(path):
    if not path or not PATH_RE.fullmatch(path):
        raise InstructionError("Unsafe or invalid secret path.")
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise InstructionError("Unsafe secret path: empty, '.' and '..' path segments are not allowed.")
    if path.startswith("/") or path.endswith("/"):
        raise InstructionError("Secret path must be relative to the 'secret' mount.")
    return path

def parse_instruction(text):
    if not isinstance(text, str) or not text.strip():
        raise InstructionError("Instruction file is empty.")
    lines = text.splitlines()
    meaningful = [(i + 1, line.strip()) for i, line in enumerate(lines) if line.strip() and not line.lstrip().startswith("#")]
    if not meaningful:
        raise InstructionError("Instruction file contains no instructions.")
    first_line_no, first = meaningful[0]
    if not first.startswith("SECRET:"):
        raise InstructionError(f"Line {first_line_no}: first meaningful line must be SECRET: <secret_path>.")
    secret_path = first[len("SECRET:"):].strip()
    validate_secret_path(secret_path)
    operations = []
    for line_no, line in meaningful[1:]:
        match = SET_RE.fullmatch(line)
        if match:
            parse_key_reference(match.group(2).strip())
            operations.append({"type": "set", "key": match.group(1), "value": match.group(2), "line": line_no})
            continue
        match = NESTED_RE.fullmatch(line)
        if match:
            parse_key_reference(match.group(3).strip())
            operations.append({"type": "set_nested", "key": match.group(1), "sub_key": match.group(2), "value": match.group(3), "line": line_no})
            continue
        raise InstructionError(f"Line {line_no}: malformed or unsupported operation.")
    if not operations:
        raise InstructionError("Instruction file must contain at least one SET or SET_NESTED operation.")
    return {"secret_path": secret_path, "operations": operations}

def apply_operations(current, operations):
    if not isinstance(current, dict):
        raise InstructionError("Vault secret data must be a key/value object.")
    result = dict(current)
    for op in operations:
        key = op["key"]
        if op["type"] == "set":
            result[key] = op["value"]
        elif op["type"] == "set_nested":
            existing = result.get(key, "")
            if not isinstance(existing, str):
                raise InstructionError(f"SET_NESTED outer key '{key}' exists but is not a string.")
            lines = existing.splitlines()
            replacement = f"{op['sub_key']}={op['value']}"
            found = False
            output = []
            for line in lines:
                stripped = line.strip()
                if "=" in stripped:
                    subkey = stripped.split("=", 1)[0].strip()
                    if subkey == op["sub_key"]:
                        if not found:
                            output.append(replacement)
                            found = True
                        # If duplicate matching subkeys already exist, collapse them to one.
                        continue
                output.append(line)
            if not found:
                output.append(replacement)
            result[key] = "\n".join(output)
        else:
            raise InstructionError("Unsupported operation.")
    return result

def build_preview(current, instruction):
    proposed = apply_operations(current, instruction["operations"])
    return {"before": current, "after": proposed, "changed": current != proposed}
