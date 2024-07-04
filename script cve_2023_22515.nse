#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import nmap
import requests

def check_CVE_2023_22515(tgt):
    """
    Проверяет наличие уязвимости CVE-2023-22515.

    Args:
        tgt (str): URL-адрес целевого сервера Confluence.

    Returns:
        bool: True, если уязвимость обнаружена, False в противном случае.
    """
    try:
        # Отправляем HTTP-запрос с заголовком "User-Agent: Confluence"
        response = requests.get(tgt, headers={'User-Agent': 'Confluence'}, timeout=5)

        # Извлекаем версию Confluence из заголовка
        version = response.headers.get('X-Confluence-Version')

        # Проверяем, что версия Confluence уязвима 
        if version:
            major, minor, _ = map(int, version.split('.'))
            if major == 8 and minor <= 5:  # Уязвимы версии 8.0.0 - 8.5.1
                print(f'CVE-2023-22515: Уязвимость обнаружена на {tgt} (версия: {version}).')
                return True
            else:
                print(f'CVE-2023-22515: Уязвимость не обнаружена на {tgt} (версия: {version}).')
                return False
        else:
            print(f'CVE-2023-22515: Не удалось получить версию Confluence с {tgt}.')
            return False

    except requests.exceptions.RequestException as e:
        print(f'Ошибка при проверке {tgt}: {e}')
        return False

def main():
    """
    Основная функция.
    """
    scanner = nmap.PortScanner()
    scanner.scan(hosts='127.0.0.1', arguments='-p 8090,8091 -sV')  # Сканируем порты Confluence
    for host in scanner.all_hosts():
        if 'http' in scanner[host]['tcp'][8090]['name'] or 'http' in scanner[host]['tcp'][8091]['name']:
            tgt = f"http://{host}:8090/rest/api/content/1234"  # Запрос к API Confluence
            check_CVE_2023_22515(tgt)

if __name__ == '__main__':
    main()