

UNKNOWN_VALUES: set[str] = {
    "",
    "-",
    "n/a",
    "unknown",
    "[unknown]",
    "(as-yet-unknown)",
    "unspecified",
    "as-yet-unknown",
}

def strip(value: str | None) -> str | None:
    if not value:
        return value

    value = value.strip()

    for suffix in (":", ",", "."):
        if value.endswith(suffix):
            value = strip(value.removesuffix(suffix))

    if "," not in value and " and " not in value.lower():
        if value.startswith("[") and value.endswith("]"):
            value = strip(value.strip("[]"))

        if value.startswith("(") and value.endswith(")"):
            value = strip(value.strip("()"))

        # A single `*` is valid for instance for versions
        if len(value) > 1 and value.startswith("*") and value.endswith("*"):
            value = strip(value.strip("*"))

    return value

def is_unknown(value: str | None) -> bool:
    if not value:
        return True

    v = strip(value).lower()

    if not v:
        return True

    # TODO: re-evaluate all of this eventually
    # A single `*` is a valid value for versions, for instance
    if v == "*":
        return False

    return v.strip("*").strip() in UNKNOWN_VALUES

def normalize(value: str | None) -> str | None:
    if is_unknown(value):
        return None
    return strip(value)
