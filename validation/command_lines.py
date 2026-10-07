import re
import shlex

SHELL_PUNCTUATION = set(";&|()<>")

# -------------------------------------------------------------
# Returns [(line_number, command)] for the lines matching command_regex,
# joining lines continued with a trailing backslash and skipping the rest
# (comments included, since they do not start with the command).
# -------------------------------------------------------------
def extract_commands(text, command_regex):
    commands = []
    pending = None
    start = 0

    for line_num, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()

        if pending is None:
            start = line_num
            pending = line
        else:
            pending += " " + line

        if pending.endswith("\\"):
            pending = pending[:-1].rstrip()
            continue

        if re.match(command_regex, pending):
            commands.append((start, pending))
        pending = None

    return commands

# -------------------------------------------------------------
# Splits a command into tokens, dropping trailing comments and anything after
# a shell operator (pipes, redirections, ';', '&&').
# Raises ValueError on unbalanced quotes.
# -------------------------------------------------------------
def tokenize_command(line):
    lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = "#"

    tokens = list(lexer)

    for idx, token in enumerate(tokens):
        if set(token) <= SHELL_PUNCTUATION:
            tokens = tokens[:idx]
            if tokens and tokens[-1].isdigit() and token.startswith(">"):
                tokens.pop()
            break

    return tokens
