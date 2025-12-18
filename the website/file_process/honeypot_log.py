import logging
from pathlib import Path
import logging
path = Path(__file__).parent

log_file = path / "honeypot_log_ip.txt"
log_file.parent.mkdir(parents=True, exist_ok=True)
import re
def the_log_append(text):
    try:
        with log_file.open("a", encoding="utf-8") as f:
            f.write(text + "\n")
    except (ValueError,IndexError,TypeError) as e:
        logging.warning(f'Type|Value|IndexError:{e}')
    except Exception as e:
        logging.warning(f'TError:{e}')
        print(f'error:{e}')

def rule(username):
    rules = [
        lambda s: re.search(
            r"name|/\*|\*/|true|<|>|=|and|or|--|'|union|select|from|drop|delete|create|update|SET|INTO|\|", s,
            re.IGNORECASE)
    ]
    for rule in rules:
        if rule(username):
            print('haha! catch u!')
    print('5')



