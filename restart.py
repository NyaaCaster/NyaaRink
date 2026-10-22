"""Production restart entry. P1 deliberately refuses until backup/preflight exists."""
from scripts.ops import main


def execute():
    raise RuntimeError('Production backup and preflight are not implemented; deployment refused')


if __name__ == '__main__': main(execute)
