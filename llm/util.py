# Map EN/EM dashes & NB hyphen to '-' and NBSP-like spaces to ' '
DASHES_MAP = dict.fromkeys(map(ord, "\u2010\u2011\u2012\u2013\u2014\u2015"), "-")
QUOTES_MAP = {0x2018: "'", 0x2019: "'", 0x201C: '"', 0x201D: '"'}
SPACES_MAP = {ord("\u00A0"): " ", ord("\u202F"): " ", ord("\u2007"): " "}

def _norm_text(s: str) -> str:
    if not isinstance(s, str):
        return s
    return s.translate(DASHES_MAP).translate(QUOTES_MAP).translate(SPACES_MAP)