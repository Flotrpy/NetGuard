import pathlib
p = pathlib.Path("netguard/scanners/sast/rules_js.py")
s = p.read_text(encoding="utf-8")

# 1. SQL concatenation: match quote types separately
old = '''            rf"(?:query|execute|raw)\s*\(\s*(?:`[^`]*{_SQL_WORDS}[^`]*\$\{{|"
            rf"['\\"][^'\\"]*{_SQL_WORDS}[^'\\"]*['\\"]\s*\+)",'''
new = '''            rf"(?:query|execute|raw)\s*\(\s*(?:`[^`]*{_SQL_WORDS}[^`]*\$\{{|"
            rf"\\"[^\\"]*{_SQL_WORDS}[^\\"]*\\"\s*\+|'[^']*{_SQL_WORDS}[^']*'\s*\+)",'''
assert old in s
s = s.replace(old, new)

# 2. innerHTML: not-a-plain-literal, immune to \s* backtracking
old = '''pattern=rx(r"\.(?:innerHTML|outerHTML)\s*\+?=\s*(?!['\\"`][^'\\"`$]*['\\"`]\s*;?\s*$)"),'''
new = '''pattern=rx(
            r"\.(?:innerHTML|outerHTML)\s*\+?=\s*(?=\S)"
            r"(?:(?!['\\"`])|['\\"`][^'\\"`]*(?:\$\{|['\\"`]\s*\+))"
        ),'''
assert old in s
s = s.replace(old, new)

# eval / document.write: same backtracking guard
s = s.replace('''(?<![\w.$])eval\s*\(\s*(?!''', '''(?<![\w.$])eval\s*\(\s*(?=\S)(?!''')
s = s.replace('''document\.write(?:ln)?\s*\(\s*(?!''', '''document\.write(?:ln)?\s*\(\s*(?=\S)(?!''')

# 3. insecure random: camelCase names
old = '''(?=.*\b(?:token|secret|password|session|nonce|otp|apikey|api_key|csrf)\b)"'''
new = '''(?=.*(?:token|secret|password|passwd|session|nonce|apikey|api_key|csrf|otp\b))"'''
assert old in s
s = s.replace(old, new)
p.write_text(s, encoding="utf-8")
