import re
from typing import Dict, List

def analyze_logs(log_text: str) -> Dict[str, List[str]]:
    """
    Анализирует логи веб-сервера на предмет атак.

    Args:
        log_text (str): Текст логов.

    Returns:
        dict: Словарь с ключами:
            - 'sql_injections': список строк с SQL-инъекциями
            - 'xss_attempts': список строк с XSS-атаками
            - 'suspicious_user_agents': список строк с подозрительными user-agent
            - 'failed_logins': список строк с неудачными логинами
    """

    sql_injections: List[str] = []
    xss_attempts: List[str] = []
    suspicious_user_agents: List[str] = []
    failed_logins: List[str] = []

    log_pattern: re.Pattern = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+'  # IP
        r'(?P<ident>\S+)\s+'               # идентификатор (-)
        r'"(?P<method>\S+)\s(?P<path>\S+)[^"]*"\s*'  # Метод и путь
        r'(?P<status>\d{3})?\s*'           # Статус 
        r'"(?P<user_agent>[^"]*)?"?'       # User-Agent
    )

    # Паттерны для SQL-инъекций
    sql_patterns: List[str] = [
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
    sql_regexes: List[re.Pattern] = [re.compile(p, re.IGNORECASE) for p in sql_patterns]

    # Паттерны для XSS атак
    xss_patterns: List[str] = [
        r"<script.*?>.*?</script>",
        r"javascript:",
        r"on\w+\s*=\s*[\"']?",
        r"<img[^>]+src=([\"'])?javascript:",
        r"alert$[^)]*$",
        r"<iframe.*?>",
        r"<svg.*?>",
        r"eval\s*$"
    ]
    xss_regexes: List[re.Pattern] = [re.compile(p, re.IGNORECASE) for p in xss_patterns]

    # Подозрительные User-Agent
    suspicious_agents: List[str] = [
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

        m: re.Match = log_pattern.search(line)
        if not m:
            print(f"Не удалось распарсить строку: {line}")
            continue

        path: str = m.group("path")
        user_agent: str = m.group("user_agent") or ""
        status: str = m.group("status") or "200"

        # Проверка на SQL-инъекции
        if any(regex.search(path) for regex in sql_regexes):
            sql_injections.append(line)

        # Проверка на XSS
        if any(regex.search(path) for regex in xss_regexes):
            xss_attempts.append(line)

        # Проверка подозрительных User-Agent
        ua_lower: str = user_agent.lower()
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

def read_log_file(filename: str) -> str:
    """
    Читает содержимое файла логов.

    Args:
        filename (str): Путь к файлу.

    Returns:
        str: содержимое файла.
    """
    with open(filename, "r", encoding="utf-8") as f:
        return f.read()

def write_results_to_file(results: Dict[str, List[str]], filename: str) -> None:
    """
    Записывает результаты анализа в файл.

    Args:
        results (dict): словарь с результатами анализа.
        filename (str): путь к файлу для сохранения.
    """
    with open(filename, "w", encoding="utf-8") as f:
        f.write("=== РЕЗУЛЬТАТЫ АНАЛИЗА ===\n")
        f.write(f"Найдено SQL инъекций: {len(results['sql_injections'])}\n")
        f.write(f"Найдено XSS попыток: {len(results['xss_attempts'])}\n")
        f.write(f"Подозрительных User-Agent: {len(results['suspicious_user_agents'])}\n")
        f.write(f"Неудачных логинов: {len(results['failed_logins'])}\n")

        f.write("\n=== ДЕТАЛИ ===\n")
        for threat_type, lines in results.items():
            if lines:
                f.write(f"\n{threat_type}:\n")
                for line in lines:
                    f.write(f"  - {line}\n")


if __name__ == "__main__":
    input_log_file: str = "server_logs.txt"  # заменить на путь к вашему файлу с логами
    output_report_file: str = "analysis_report.txt"  # файл для вывода результата

    logs: str = read_log_file(input_log_file)
    results: Dict[str, List[str]] = analyze_logs(logs)
    write_results_to_file(results, output_report_file)

    print(f"Анализ завершён. Результаты записаны в {output_report_file}")
