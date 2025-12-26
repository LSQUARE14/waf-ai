import numpy as np
import torch
from transformers import AutoTokenizer, AutoModel
from typing import List, Union
from tqdm.auto import tqdm
import pandas as pd
import re
import urllib.parse
import html
from typing import Optional
import numpy as np
import pandas as pd
import xgboost as xgb

MODEL_NAME = "jackaduma/SecBERT"
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
_tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
_model = AutoModel.from_pretrained(MODEL_NAME).to(device)
_model.eval()

def _l2_normalize_batch(x: np.ndarray, eps: float = 1e-12) -> np.ndarray:
    norms = np.linalg.norm(x, axis=1, keepdims=True)
    return x / (norms + eps)

def secbert_extract_flexible(
    inputs: Union[List[str], List[List[str]], pd.Series],
    batch_size: int = 64,
    max_length: int = 128,
    pooling: str = "mean",
    normalize: bool = False,
    show_progress: bool = True,
) -> np.ndarray:

    # Chuẩn hóa đầu vào về list
    if isinstance(inputs, pd.Series):
        inputs = inputs.tolist()

    if all(isinstance(x, str) for x in inputs):
        texts = inputs

    else:
        raise ValueError("Input must be list[str] or pd.Series of str.")

    all_embs = []
    iterator = range(0, len(texts), batch_size)
    if show_progress:
        iterator = tqdm(iterator, desc="SecBERT embedding", unit="batch")

    for i in iterator:
        batch_texts = texts[i:i+batch_size]
        enc = _tokenizer(
            batch_texts,
            return_tensors="pt",
            truncation=True,
            padding="max_length",
            max_length=max_length,
            add_special_tokens=True
        ).to(device)

        with torch.no_grad():
            out = _model(**enc)
            hidden = out.last_hidden_state

        mask = enc.attention_mask.unsqueeze(-1).expand(hidden.size()).float()
        if pooling == "max":
            batch_emb = torch.max(hidden, dim=1).values
        elif pooling == "mean":
            summed = torch.sum(hidden * mask, dim=1)
            counts = torch.clamp(mask.sum(1), min=1e-9)
            batch_emb = summed / counts
        elif pooling == "cls":
            batch_emb = hidden[:, 0, :]
        else:
            raise ValueError("pooling must be 'mean' or 'cls'")

        batch_emb = batch_emb.cpu().numpy()
        if normalize:
            batch_emb = _l2_normalize_batch(batch_emb)

        all_embs.append(batch_emb)

    embeddings = np.vstack(all_embs)
    return embeddings.astype(np.float32)

def is_mostly_printable(s: bytes, threshold: float = 0.95) -> bool:
    """Return True if fraction of printable (and common whitespace) bytes in s >= threshold."""
    if not s:
        return False
    printable = 0
    for b in s:
        # allow 9(tab),10(lf),13(cr) and 32..126 printable ASCII
        if b in (9,10,13) or 32 <= b <= 126:
            printable += 1
    return (printable / len(s)) >= threshold

def try_decode_hex(hexstr: str) -> Optional[str]:
    """Try to decode a hex string (even-length). Return decoded text if mostly printable, else None."""
    # ensure even length
    if len(hexstr) % 2 == 1:
        # if odd, prefix a 0
        hexstr = '0' + hexstr
    try:
        data = bytes.fromhex(hexstr)
    except Exception:
        return None
    if is_mostly_printable(data):
        try:
            return data.decode('utf-8', errors='strict')
        except Exception:
            # fallback to latin-1 if utf-8 fails but bytes are printable
            try:
                return data.decode('latin-1', errors='replace')
            except Exception:
                return None
    return None

def try_decode_0x_match(m: re.Match) -> str:
    """Replace 0x... hex literal if decodes to printable text, else return original match."""
    full = m.group(0)
    hx = m.group(1)
    decoded = try_decode_hex(hx)
    if decoded is not None:
        return decoded
    return full

def try_decode_hex_sequence(m: re.Match) -> str:
    token = m.group(0)
    decoded = try_decode_hex(token)
    if decoded is not None:
        return decoded
    return token

def try_decode_decimal_sequence(m: re.Match) -> str:
    token = m.group(0)
    try:
        n = int(token, 10)
        # convert integer to minimal bytes
        length = (n.bit_length() + 7) // 8 or 1
        data = n.to_bytes(length, 'big')
        if is_mostly_printable(data):
            try:
                return data.decode('utf-8', errors='strict')
            except Exception:
                return data.decode('latin-1', errors='replace')
    except Exception:
        pass
    return token

HEX_0X_RE = re.compile(r'0x([0-9a-fA-F]{6,})')  # 0x + at least 6 hex chars
# long even-length hex sequences (word boundaries) of >=6 chars and even length
HEX_SEQ_RE = re.compile(r'\b([0-9a-fA-F]{6,})\b')
# decimal sequences of length >=6 (likely to be encoded data if long)
DEC_SEQ_RE = re.compile(r'\b(\d{6,})\b')

def convert_long_numbers(s: str) -> str:
    """Find 0x-hex, plain hex sequences, and long decimal sequences and try to decode them to strings."""
    # 1) 0x... replacements
    s = HEX_0X_RE.sub(lambda m: try_decode_0x_match(m), s)
    # 2) plain hex sequences: only replace if length is even or produces printable output when padded
    def hex_repl(m):
        token = m.group(1)
        # Only attempt if token length is even or will be padded (we handle odd by padding inside try_decode_hex)
        decoded = try_decode_hex(token)
        if decoded is not None:
            return decoded
        return token
    s = HEX_SEQ_RE.sub(lambda m: hex_repl(m), s)
    # 3) decimal sequences: try to convert large integers to bytes and decode if printable
    s = DEC_SEQ_RE.sub(lambda m: try_decode_decimal_sequence(m), s)
    return s

def decode_recursive(s: str, max_iters: int = 10) -> str:
    """Recursively URL-decode and HTML-unescape a string, and convert long hex/dec sequences.
       Stop when no further changes occur or max_iters is reached.
    """
    prev = None
    cur = s
    for i in range(max_iters):
        # 1) URL-decode (percent decoding)
        try:
            url_decoded = urllib.parse.unquote(cur)
        except Exception:
            url_decoded = cur
        # 2) HTML unescape
        html_decoded = html.unescape(url_decoded)
        # 3) convert long numeric/hex tokens
        converted = convert_long_numbers(html_decoded)
        if converted == prev:
            # stable
            break
        prev = cur
        cur = converted
    return cur

def preprocess_payloads(payloads: List[str]) -> List[str]:
    """Preprocess payloads by recursively decoding and normalizing."""
    preprocessed = []
    for p in payloads:
        decoded = decode_recursive(p)
        preprocessed.append(decoded)
    return preprocessed

class XGBoostDetector:
    def __init__(self, model_path: str):
        self.model = xgb.Booster()
        self.model.load_model(model_path)

    def predict(self, payloads: List[str]) -> bool:
        preprocessed_payloads = preprocess_payloads(payloads)
        embeddings = secbert_extract_flexible(
            preprocessed_payloads,
            batch_size=64,
            pooling="mean",
            normalize=True,
            show_progress=True
        )
        dmatrix = xgb.DMatrix(embeddings)
        preds = self.model.predict(dmatrix)

        labels = ["anom" if p >= 0.5 else "norm" for p in preds]
        return all(label == "norm" for label in labels)
