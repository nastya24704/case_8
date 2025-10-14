# Part of a case-study #8: Operation "Data Shield"
# Developers: Lagoda K., Zheravina A., Pinoeva K., Mozhaitseva M.


import re
import regex
from typing import Dict, List


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
        if i % 2 == 0:
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

    part = r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'  # шаблон для IP4, далее его *4#
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

    report = {
        'financial_data': find_and_validate_credit_cards(main_text),
        'secrets': find_secrets(main_text),
        'system_info': find_system_info(main_text),
        'security_threats': analyze_logs(log_text),
    }
    return report


def print_report(report: Dict) -> None:
    '''
    Outputs the report in a readable format.

    Args:
        report (Dict): Generated report for output

    Returns:
        None: The function returns nothing, only print
    '''

    print("=" * 50)
    print("ОТЧЕТ ОПЕРАЦИИ 'DATA SHIELD'")
    print("=" * 50)

    print("\nФИНАНСОВЫЕ ДАННЫЕ:")
    print(report['financial_data'])

    print("\nСЕКРЕТНЫЕ КЛЮЧИ:")
    for s in report['secrets']:
        print(f" - {s}")

    print("\nСИСТЕМНАЯ ИНФОРМАЦИЯ:")
    for k, v in report['system_info'].items():
        print(f" {k.upper()}: {', '.join(v) if v else '—'}")

    print("\nУГРОЗЫ БЕЗОПАСНОСТИ:")
    for k, v in report['security_threats'].items():
        print(f" {k}: {len(v)} найдено")

    results = analyze_logs(log_text)
    print("=== РЕЗУЛЬТАТЫ АНАЛИЗА ===")
    print(f"Найдено SQL инъекций: {len(results['sql_injections'])}")
    print(f"Найдено XSS попыток: {len(results['xss_attempts'])}")
    print(f"Подозрительных User-Agent: {len(results['suspicious_user_agents'])}")
    print(f"Неудачных логинов: {len(results['failed_logins'])}")

    # Детальный вывод
    print("\n=== ДЕТАЛИ ===")
    for threat_type, lines in results.items():
        if lines:
            print(f"\n{threat_type}:")
            for line in lines:
                print(f" - {line}")



if __name__ == "__main__":
    # Чтение файлов с данными
    with open('data_leak_sample.txt', 'r', encoding='utf-8') as f:
        main_text = f.read()

    with open('web_server_logs.txt', 'r', encoding='utf-8') as f:
        log_text = f.read()

    with open('messy_data.txt', 'r', encoding='utf-8') as f:
        messy_data = f.read()


    # Запуск расследования
    report = generate_comprehensive_report(main_text, log_text, messy_data)
    print_report(report)
