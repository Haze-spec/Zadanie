1. CVE-2023-22515 - это уязвимость типа **"Server-Side Request Forgery (SSRF)"**, 
Ключевой момент атаки заключается в том, что уязвимые версии Confluence Data Center и Confluence Server позволяют без аутентификации на сервере поменять значение атрибута  bootstrapStatusProvider.applicationConfig.setupComplete на  false . Тем самым атакующие реинициализируют этап начальной настройки сервера и получают возможность бесконтрольно создавать на нем собственные учетные записи администраторов.

**Механизм уязвимости:**

1.1 **Некорректная обработка URL:**  Уязвимость возникает, когда злоумышленник может ввести специально сформированный URL в поле ввода веб-формы, которая отправляет HTTP-запрос.
1.2 **Запрос к внутренним серверам:**  Вместо отправки запроса на внешний сервер, Content Formatter отправляет запрос на внутренний сервер, например, на сервер базы данных или на сервер приложений.
1.3 **Проникновение в систему:**  Злоумышленник может использовать эту возможность для получения доступа к конфиденциальной информации, перехватить сеансы аутентификации, управлять сервером, а также получить доступ к внутренним сетям.


**список уязвимых версий по информации, опубликованной Atlassian**

8.0.0, 8.0.1, 8.0.2, 8.0.3, 8.0.4;
8.1.0, 8.1.1, 8.1.3, 8.1.4;
8.2.0, 8.2.1, 8.2.2, 8.2.3;
8.3.0, 8.3.1, 8.3.2;
8.4.0, 8.4.1, 8.4.2;
8.5.0, 8.5.1.

2. **NSE скрипт для Nmap**

2.1 Стандартный NSE интерфейс:
   *   `main(host, port)`  -  основная  функция  скрипта,  которая  принимает  IP-адрес  `host`  и  порт  `port`. 
   *   Возвращает  таблицу  с  результатами,  включая  `result`  (boolean),  `version`  (если  она  была  получена),  и  `output`  (текстовое  сообщение  с  результатами  сканирования).
2.2 `script`  таблица:
   *   `name`:  Имя  скрипта  (будет  использоваться  при  вызове  `-script`).
   *   `author`:  Имя  автора  скрипта.
   *   `description`:  Краткое  описание  скрипта.
   *   `categories`:  Категории  скрипта  (в  данном  случае  `exploit`,  `vuln`,  `default`).
   *   `license`:  Лицензия  скрипта.
   *   `targets`:  Таблица  целей,  для  которых  предназначен  скрипт  (в  данном  случае  `Confluence`,  порт  `8090`,  протокол  `tcp`,  версия  `8.0.0 - 8.5.1`).
   *   `main`:  Функция  `main`,  которая  будет  вызвана  Nmap  для  запуска  скрипта.
2.3 `nmap.register_script(script)`:  Регистрирует  скрипт  в  Nmap.

3. **Простой и быстрый способ протестировать работу скрипта**


3.1 Запустите  Docker  Compose  для  создания  тестовой  среды  Confluence
3.2 Скопируйте  файл  в  каталог  скриптов  Nmap
3.3 Запустите  Nmap  с  использованием  скрипта(cve_2023_22515.nse ):
   
    nmap -sV -p 8090 -iL target.txt -script cve_2023_22515.nse
   
    * `-sV`:  Определяет  версию  сервиса,  работающего  на  сканируемом  порте.
    * `-p 8090`:  Сканирует  только  порт  8090  (стандартный  порт  для  Confluence).
    * `-iL target.txt`:  Указывает  файл  `target.txt`  с  IP-адресом  контейнера  `confluence_vulnerable`.  В  файле  `target.txt`  должен  быть  только  IP-адрес  контейнера.
3.4 Проверьте  вывод  Nmap  на  наличие  сообщения  об  обнаружении  уязвимости  или  ее  отсутствии.

4. **Скрытие уязвимости**

Администратор может попытаться скрыть уязвимость следующими способами:

* **Обновление Confluence Server:**  Установка последнего патча, который исправляет CVE-2023-22515, является лучшим способом защититься от этой уязвимости.
* **Блокировка HTTP-запросов с заголовком "User-Agent: Confluence":**  Админ может настроить веб-сервер, чтобы блокировать запросы с указанным заголовком.
* **Ограничение доступа к веб-серверу:** Ограничение доступа к Confluence Server только для доверенных пользователей может предотвратить злонамеренные атаки.
* **Использование WAF:**  Использование веб-приложения для защиты от атак (WAF) для блокировки вредоносных запросов.
