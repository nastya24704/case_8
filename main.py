# Part of a case-study #8: Operation "Data Shield"
# Developers: Lagoda K., Zheravina A., Pinoeva K., Mozhaitseva M.


import re
import regex
from typing import Dict, List
from datetime import datetime
import codecs
import binascii
import base64


def num_card(text: str) -> str:
    '''
    Extracts only numbers from the text to get the card number.

    Args:
        text (str): The text containing the card number

    Returns:
        str: A string containing only the digits of the card number
    '''
    return re.sub(r'\D', '', text)


def check_luhn(text: str) -> bool:
    '''
    Checks the card number using the Luna algorithm.

    Args:
        text (str): The text containing the card number

    Returns:
        True if the card number is valid, otherwise False
    '''

    total_sum = 0
    card = num_card(text)

    for i in range(len(card)):
        num_text = int(card[i])
        if i % 2 == 0 :
            if num_text * 2 > 9:
                total_sum += (2 * num_text) - 9
            else:
                total_sum += 2 * num_text
        else:
            total_sum += num_text

    return total_sum % 10 == 0


def find_and_validate_credit_cards(text: str) -> Dict[str, List[str]]:
    '''
    Finds and verifies credit card numbers in the text.
    
    Args:
        text (str): Text for searching for card numbers
        
    Returns:
        Dictionary with 'valid' and 'invalid' keys containing lists 
        valid and invalid card numbers
    '''

    pattern_1 = r'(?:\d ?[ -]? ?){13,19}'
    card_in_text = re.findall(pattern_1, text)

    pattern_2 = r'\b(?:\d{4} ?[- ]? ?){3}\d{4}\b'
    potential_cards = re.findall(pattern_2, text)

    result = {'valid': [], 'invalid': []}

    for num in card_in_text:
        if num in potential_cards and check_luhn(num):
            result['valid'].append(num)
        else:
            result['invalid'].append(num)

    return result


def find_secrets(text: str) -> List[str]:
    '''
    Searches for API keys, passwords, access tokens

    Args:
        text (str): the text being checked gor secrets

    Returns: a list of found secrets
    '''

    keys = [
        r'sk_(?:live|test)_[0-9a-zA-Z]{24,}',
        r'pk_(?:live|test)_[0-9a-zA-Z]{24,}',

        r'gh[pousr]_[a-zA-Z0-9]{36}',

        r'eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}',

        r'\b[a-zA-Z0-9]{32,64}\b',

        r'(?i)(password|pwd|secret|key|token|passwd)[\
        s:=]+["\']?([A-Za-z0-9!@#$%^&*()_+\-=\[\]{}|;:,.<>?]{8,})["\']?',

        r'(?:api[_\-]?key|api-ключи?)[\s:=]+["\']?[A-Za-z0-9]{32,}["\']?',

        r'AKIA[0-9A-Z]{16}',

        r'AIza[0-9A-Za-z_-]{35}',

        r'Basic\s+[a-zA-Z0-9=+/]{20,}',
        r'Bearer\s+[a-zA-Z0-9._-]+',

        r'\b[A-Za-z0-9!@#$%^&*()_+\-=\[\]{}|;:,.<>?]{8,}\b',
    ]

    secrets = []

    for key in keys:
        results = re.finditer(key, text)
        for match in results:
            if match.groups():
                secret = match.group(1)
                if secret:
                    secrets.append(secret)
            else:
                secrets.append(match.group(0))

    return list(set(secrets))


def find_system_info(text: str) -> Dict[str, List[str]]:
    '''
    Searches for system information(IP, files, emails)
    based on name characteristics

    Args:
        text (str): data from file
    Returns:
        {'ips': [], 'files': [], 'emails': []}
    '''

    part = r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)' #шаблон для IP4, далее его *4#
    ipv4 = rf'(?:{part}\.){{3}}{part}'
    ipv6 = (
        r'(?:'
        r'(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}'  # полная форма
        r'|'
        r'(?:[A-F0-9]{1,4}:){1,7}:'  # :: в конце
        r'|'
        r'(?:[A-F0-9]{1,4}:){1,6}:[A-F0-9]{1,4}'  # :: в середине
        r'|'
        r'(?:[A-F0-9]{1,4}:){1,5}(?::[A-F0-9]{1,4}){1,2}'
        r'|'
        r'(?:[A-F0-9]{1,4}:){1,4}(?::[A-F0-9]{1,4}){1,3}'
        r'|'
        r'(?:[A-F0-9]{1,4}:){1,3}(?::[A-F0-9]{1,4}){1,4}'
        r'|'
        r'(?:[A-F0-9]{1,4}:){1,2}(?::[A-F0-9]{1,4}){1,5}'
        r'|'
        r'[A-F0-9]{1,4}:(?:(?::[A-F0-9]{1,4}){1,6})'
        r'|'
        r'::1'  # ::1
        r'|'
        r'::'  # ::
        r')'
    )

    # объединяем IPv4 и IPv6
    ip_pattern = regex.compile(rf'(?:{ipv4}|{ipv6})', regex.IGNORECASE)

    # Email
    email_pattern = regex.compile(
        r'\b'
        r"[A-Z0-9!#$%&'*+/=?^_`{|}~-]{1,64}"
        r'@'
        r"(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[\p{L}]{2,63}"
        r'\b',
        regex.IGNORECASE | regex.UNICODE
    )

    # Файлы
    files_pattern = regex.compile(
    r'\b[A-Z0-9_(){}\-]+\.(?:txt|docx?|pdf|png|jpg|jpeg|exe|csv|py|html|json|xml|zip|rar)\b',
        regex.IGNORECASE
    )

    ips = [m.group(0) for m in ip_pattern.finditer(text)]
    files = [m.group(0) for m in files_pattern.finditer(text)]
    emails = [m.group(0) for m in email_pattern.finditer(text)]

    return {'ips': ips, 'files': files, 'emails': emails}


def decode_messages(text: str) -> Dict[str, List[str]]:
    """
    Finds and decrypts messages in text:
    - Base64 (strings, length multiple of 4; trailing =/== allowed)
    - Hex: 0x... or \\xHH\\xHH...
    - ROT13 (simple attempt: words/phrases of letters and numbers)
    Returns a dictionary {'base64': [...], 'hex': [...], 'rot13': [...]}
    """

    base64_pattern = regex.compile(r'\b(?:[A-Z0-9+/]{4}){2,}(?:==|=)?\b',
    regex.IGNORECASE
              )
    base_decoded = []
    for match in base64_pattern.findall(text):
        if len(match) % 4 != 0:
            continue
        try:
            # validate=True заставит b64decode выдавать ошибку, если есть недопустимые символы
            decoded_bytes = base64.b64decode(match, validate=True)
            decoded = decoded_bytes.decode('utf-8')
        except (binascii.Error, UnicodeDecodeError):
            continue
        if decoded.isprintable():
            base_decoded.append(decoded)

    hex_pattern = regex.compile(r'0x[0-9A-F]+|(?:\\x[0-9A-Fa-f]{2})+',
    regex.IGNORECASE
    )
    hex_decoded = []
    for match in hex_pattern.findall(text):
        try:
            if match.startswith("0x") or match.startswith('0X'):
                # убираем префикс 0x и переводим hex в байты
                hexstr = match[2:]
                # если длина нечётная — некорректно
                if len(hexstr) % 2 != 0:
                    continue
                bytes_data = bytes.fromhex(hexstr)
            else:
                # match содержит последовательности вида '\x48\x65...'
                # извлечём все пары HH через поиск групп
                pairs = regex.findall(r'\\x([0-9A-Fa-f]{2})', match)
                if not pairs:
                    continue
                bytes_data = bytes.fromhex(''.join(pairs))
            decoded = bytes_data.decode('utf-8')
        except (ValueError, UnicodeDecodeError):
            continue
        if decoded.isprintable():
            hex_decoded.append(decoded)

    rot13_pattern = regex.compile(r'\b[A-Za-z0-9!?.]+(?:\s[A-Za-z0-9!?.]+)*\b')
    rot13_decoded = []
    for match in rot13_pattern.findall(text):
        decoded = codecs.decode(match, 'rot_13')
        # фильтры: должно отличаться и быть читаемым
        if decoded.isprintable() and decoded.lower() != match.lower():
            rot13_decoded.append(decoded)

    return {
        'base64': base_decoded,
        'hex': hex_decoded,
        'rot13': rot13_decoded
    }



def analyze_logs(log_text: str) -> Dict[str, List[str]]:
    '''
    Analyzes the logs of the web server for attacks.

    Args:
        log_text (str): The text of the logs for analysis

    Returns:
        Dictionary of detected threats by category:
        - sql_injections: SQL injections
        - xss_attempts: XSS attacks
        - suspicious_user_agents: suspicious User-Agent
        - failed_logins: failed login attempts
    '''


    sql_injections = []
    xss_attempts = []
    suspicious_user_agents = []
    failed_logins = []

    log_pattern = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+'  # IP
        r'(?P<ident>\S+)\s+'  # идентификатор (-)
        r'"(?P<method>\S+)\s(?P<path>\S+)[^"]*"\s*'  # Метод и путь
        r'(?P<status>\d{3})?\s*'  # Статус 
        r'"(?P<user_agent>[^"]*)?"?'  # User-Agent
    )

    # Паттерны для SQL-инъекций
    sql_patterns = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(\#)|(\%3D)|(\='\")",
        r"UNION\s+SELECT",
        r"\sOR\s+\d+=\d+",
        r"sleep$\d+$",
        r"SELECT\s+\*",
        r"DROP\s+TABLE",
        r"INSERT\s+INTO",
        r"1=1",
        r"WAITFOR\s+DELAY"
    ]
    sql_regexes = [re.compile(p, re.IGNORECASE) for p in sql_patterns]

    # Паттерны для XSS атак
    xss_patterns = [
        r"<script.*?>.*?</script>",
        r"javascript:",
        r"on\w+\s*=\s*[\"']?",
        r"<img[^>]+src=([\"'])?javascript:",
        r"alert$[^)]*$",
        r"<iframe.*?>",
        r"<svg.*?>",
        r"eval\s*$"
    ]
    xss_regexes = [re.compile(p, re.IGNORECASE) for p in xss_patterns]

    # Подозрительные User-Agent
    suspicious_agents = [
        "sqlmap",
        "havij",
        "nikto",
        "acunetix",
        "bot",
        "crawler",
        "scanner",
        "nessus",
        "metasploit",
        "evilbot"
    ]

    for line in log_text.splitlines():
        line = line.strip()
        if not line:
            continue

        m = log_pattern.search(line)
        if not m:
            print(f"Не удалось распарсить строку: {line}")
            continue

        path = m.group("path")
        user_agent = m.group("user_agent") or ""
        status = m.group("status") or "200"

        # Проверка на SQL-инъекции
        if any(regex.search(path) for regex in sql_regexes):
            sql_injections.append(line)

        # Проверка на XSS
        if any(regex.search(path) for regex in xss_regexes):
            xss_attempts.append(line)

        # Проверка подозрительных User-Agent
        ua_lower = user_agent.lower()
        if any(sig in ua_lower for sig in suspicious_agents):
            suspicious_user_agents.append(line)

        # Проверка неудачных логинов
        if status == "401" or "login failed" in line.lower():
            failed_logins.append(line)

    return {
        'sql_injections': sql_injections,
        'xss_attempts': xss_attempts,
        'suspicious_user_agents': suspicious_user_agents,
        'failed_logins': failed_logins
    }


def leap_year(year: int) -> bool:
    """
    Determine whether a given year is a leap year.

    Args:
        year (int): The year to check.

    Returns:
        bool: True if the year is a leap year, False otherwise.
    """
    return (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0)


def days_check(month: int, year: int, day: int) -> bool:
    """
    Check if the given day is valid for the specified month and year.

    Args:
        month (int): Month number (1-12).
        year (int): Year number.
        day (int): Day number.

    Returns:
        bool: True if the day is valid for the month, False otherwise.
    """

    if month in [4, 6, 9, 11] and day > 30:
        return False

    if month == 2:
        if leap_year(year) and day > 29:
            return False
        elif not leap_year(year) and day > 28:
            return False

    return True


def add_spase(text: str) -> str:
    text_list = []
    text = str(text)

    for i in range(16):
        if (i + 1) % 4 != 0:
            text_list.append(text[i])
        else:
            text_list.append(text[i])
            text_list.append(" ")

    return "".join(text_list)


def parse_date(date_str: str):
    formats = ['%d.%m.%Y', '%Y/%m/%d', '%d-%b-%Y', '%d-%m-%Y','%d/%m/%Y','%d-%m-%Y',
                    '%Y.%m.%d', '%Y-%m-%d', '%d/%b/%Y', '%d.%b.%Y' ,'%Y-%b-%d',
                    '%Y.%b.%d', '%d-%B-%Y', '%d/%B/%Y', '%d.%B.%Y', '%Y-%B-%d','%Y.%B.%d']

    for fmt in formats:
        try:
            dt = datetime.strptime(date_str, fmt)
            return dt.strftime('%d.%m.%Y')
        except ValueError:
            continue

    return None


def phones(data1):
    result = {
        'phones': {'valid': [], 'invalid': []},
        'dates': {'normalized': [], 'invalid': []},
        'inn': {'valid': [], 'invalid': []},
        'cards': {'valid': [], 'invalid': []}
             }

    data_num = data1.get('phones', [])
    pattern = (r"(\+7|8|007)[ ]?[\-*.(]?\d{3}[)\-*.]?[ ]?"
               r"\d{3}[ \-\.]?\d{2}[ \-\.]?\d{2}")

    for phone in data_num:
        number_match = re.match(pattern, phone)
        if number_match:
            first_num = number_match.group(0)
            number_digits = re.sub(r'\D', '', phone)
            if first_num.startswith("+7") or first_num.startswith("7"):
                if first_num.startswith("+7"):
                    normal_phone = "+7" + number_digits[1:]
                else:
                    normal_phone = "+7" + number_digits[1:]
                result['phones']['valid'].append(normal_phone)
            elif first_num.startswith("8"):
                normal_phone = "+7" + number_digits[1:]
                result['phones']['valid'].append(normal_phone)
            elif first_num.startswith("007"):
                normal_phone = "+7" + number_digits[3:]
                result['phones']['valid'].append(normal_phone)
            else:
                normal_phone = "+7" + number_digits
                result['phones']['valid'].append(normal_phone)
        else:
            result['phones']['invalid'].append(phone)

    for date_str in data1.get('dates', []):
        date_str = date_str.strip()
        normalized = parse_date(date_str)
        dt = datetime.strptime(normalized, '%d.%m.%Y')
        year = dt.year
        month = dt.month
        day = dt.day
        if normalized and days_check(month, year, day):
            result['dates']['normalized'].append(normalized)
        else:
            result['dates']['invalid'].append(date_str)

    for inn in data1.get('inn', []):
        if not re.fullmatch(r'\d+', inn):
            result['inn']['invalid'].append(inn)
        else:
            inn_digits = inn
            if len(inn_digits) in (10, 12):
                result['inn']['valid'].append(inn_digits)
            else:
                result['inn']['invalid'].append(inn)

    for card in data1.get('cards', []):
        pattern_2 = r'\b(?:\d{4} ?[- ]? ?){3}\d{4}\b'
        potential_cards = re.match(pattern_2, card)
        if potential_cards:
            if check_luhn(num_card(card)):
                card_digits = num_card(card)
                result['cards']['valid'].append(add_spase(card_digits))
            else:
                card_digits = num_card(card)
                result['cards']['invalid'].append(add_spase(card_digits))
        else:
            card_digits = num_card(card)
            result['cards']['invalid'].append(add_spase(card_digits))
    return result


def read_and_parse(filepath: str) -> Dict[str, List[str]]:
    data = {
        'phones': [],
        'dates': [],
        'inn': [],
        'cards': []
    }

    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue


            parts = line.split(':', 1)
            if len(parts) != 2:
                continue

            category = parts[0].strip().lower()
            values_str = parts[1].strip()

            values = re.split(r'[;,]', values_str)
            values = [vl.strip() for vl in values if vl.strip()]

            if category == 'телефоны':
                for vl in values:
                    data['phones'].append(vl)
            elif category == 'даты':
                for vl in values:
                    data['dates'].append(vl)
            elif category == 'инн':
                for vl in values:
                    data['inn'].append(vl)
            elif category == 'карты':
                for vl in values:
                    data['cards'].append(vl)
    return data


def generate_comprehensive_report(main_text: str, log_text: str,
                                  messy_data: str) -> Dict:
    '''
    Generates a full investigation report.

    Args:
        main_text: The main text for analysis
        log_text: The text of the logs for security analysis
        messy_data: Additional data for analysis

    Returns:
        A full report with all the data and threats found
    '''

    parsed_data = read_and_parse(messy_data)
    normalized_data = phones(parsed_data)

    report = {
        'financial_data': find_and_validate_credit_cards(main_text),
        'secrets': find_secrets(main_text),
        'system_info': find_system_info(main_text),
        'encoded_massages': decode_messages(main_text),
        'security_threats': analyze_logs(log_text),
        'normalized_data': normalized_data
    }
    return report


def save_report_to_file(report: Dict, filename: str = "report.txt") -> None:
    """
    Сохраняет отчёт в текстовый файл.

    Args:
        report (Dict): Сгенерированный отчёт
        filename (str): Имя файла для сохранения
    """

    with open(filename, "w", encoding="utf-8") as f:
        f.write("=" * 50 + "\n")
        f.write("ОТЧЕТ ОПЕРАЦИИ 'DATA SHIELD'\n")
        f.write("=" * 50 + "\n\n")

        f.write("ФИНАНСОВЫЕ ДАННЫЕ:\n")
        f.write(str(report['financial_data']) + "\n\n")

        f.write("СЕКРЕТНЫЕ КЛЮЧИ:\n")
        for s in report['secrets']:
            f.write(f" - {s}\n")
        f.write("\n")

        f.write("СИСТЕМНАЯ ИНФОРМАЦИЯ:\n")
        for k, v in report['system_info'].items():
            f.write(f" {k.upper()}: {', '.join(v) if v else '—'}\n")
        f.write("\n")

        f.write("РАСШИФРОВАННЫЕ СООБЩЕНИЯ:\n")
        for k, v in report['encoded_massages'].items():
            if v:
                f.write(f" {k}: {(v)} \n")
        f.write("\n")

        f.write("УГРОЗЫ БЕЗОПАСНОСТИ:\n")
        for k, v in report['security_threats'].items():
            f.write(f" {k}: {(v)} \n")
        f.write("\n")

        f.write("НОРМАЛИЗОВАННЫЕ ДАННЫЕ:\n")
        normalized = report.get('normalized_data', {})
        for category, data in normalized.items():
            valid_count = (data.get('valid', []))
            invalid_count = (data.get('invalid', []))
            f.write(f" {category}: {valid_count} валидных, {invalid_count} невалидных\n")

    print(f"\nОтчёт сохранён в файл: {filename}")


if __name__ == "__main__":
    # Чтение исходных данных
    with open('data_leak_sample.txt', 'r', encoding='utf-8') as f:
        main_text = f.read()

    with open('web_server_logs.txt', 'r', encoding='utf-8') as f:
        log_text = f.read()

    with open('messy_data.txt', 'r', encoding='utf-8') as f:
        messy_data = f.read()

    # Генерация отчёта
    report = generate_comprehensive_report(main_text, log_text, 'messy_data.txt')

    # Сохранение отчёта в файл
    save_report_to_file(report, "report.txt")
