import re
import sys

# simple log scrubber: masks onion hosts, tokens, and s3 URIs.
PATTERNS = [
    (re.compile(r"\b[a-z2-7]{56}\.onion\b", re.IGNORECASE), "<onion-redacted>"),
    (re.compile(r"(Bearer\s+)[A-Za-z0-9\-\._~\+\/]+=*", re.IGNORECASE), r"\1<token-redacted>"),
    (re.compile(r"s3:\/\/[a-z0-9\-]+\/[A-Za-z0-9\-\/_\.]+", re.IGNORECASE), "s3://<redacted>"),
]

def scrub(text: str) -> str:
    for rx, repl in PATTERNS:
        text = rx.sub(repl, text)
    return text

if __name__ == "__main__":
    data = sys.stdin.read()
    sys.stdout.write(scrub(data))
