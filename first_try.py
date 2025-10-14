import re


def analyze_logs(log_text):
    """
    Анализирует логи веб-сервера на предмет атак
    """
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
        r"sleep\(\d+\)",
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
        r"alert\([^)]*\)",
        r"<iframe.*?>",
        r"<svg.*?>",
        r"eval\s*\("
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


logs = '''
192.168.1.100 - "GET /search?q=<script>alert('xss')</script>" 200 "Mozilla"
203.0.113.5 - "GET /admin" 401 "EvilBot/1.0"
10.0.0.50 - "GET /products?id=1' OR '1'='1" 200 "Chrome"
94.130.12.45 - "GET /test?cmd=sleep(5)" 200 "sqlmap"
'''

results = analyze_logs(logs)
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
            print(f"  - {line}")
