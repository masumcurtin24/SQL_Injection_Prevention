# backend/security/sql_normalizer.py
import re
import unicodedata
from typing import Tuple

_mysql_version_comment = re.compile(r"/\*!\d{3,5}\s*", re.IGNORECASE)
_c_block_comment = re.compile(r"/\*.*?\*/", re.DOTALL)
_dash_comment = re.compile(r"--[^\S\r\n]?.*$", re.MULTILINE)
_hash_comment = re.compile(r"#[^\n]*$", re.MULTILINE)
_ws = re.compile(r"\s+")


HOMOGLYPHS = {
    # Common confusable Latin lookalikes from Cyrillic/Greek
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "N", "О": "O", "Р": "P", "С": "S", "Т": "T", "Х": "X",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "s", "х": "x",
    "Ι": "I", "Ο": "O", "Ρ": "P", "Χ": "X", "Υ": "Y",
}

def _fold_homoglyphs(s: str) -> str:
    return ''.join(HOMOGLYPHS.get(ch, ch) for ch in s)

def canonicalize(sql: str) -> Tuple[str, dict]:
    """Return a normalized version of SQL for analysis:
    - Strip MySQL versioned comments, C-style blocks, -- and # comments
    - Normalize whitespace to single spaces
    - Lowercase
    - Preserve a small map with removed-comment flags for debugging
    """
    if not isinstance(sql, str):
        return "", {"empty": True}
    original = sql
    s = sql
    try:
        # Unicode normalization + homoglyph fold
        s = unicodedata.normalize('NFKC', s)
        s = _fold_homoglyphs(s)
        s = _mysql_version_comment.sub(" ", s)
        s = _c_block_comment.sub(" ", s)
        s = _dash_comment.sub(" ", s)
        s = _hash_comment.sub(" ", s)
        s = _ws.sub(" ", s).strip()
        s = s.lower()
    except Exception:
        # If normalization fails, fall back to original lower/space collapse
        s = _ws.sub(" ", original).strip().lower()
    meta = {
        "len_before": len(original or ""),
        "len_after": len(s),
    }
    return s, meta
