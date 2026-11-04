# 11. Источники IP → ASN для сводки клиентов

Статус: **исследование** (2026-11-04), к решению владельца о сводке от клиентов: k = 10, хранение 30 дней,
сводка — необязательная метрика (ответ клиенту: [handoff/niko-r14-reply.md](handoff/niko-r14-reply.md) §4).
Источник ASN ещё не выбран. Ключевые условия перепроверены отдельно по первоисточникам:
- DB-IP Lite — CC BY, в FAQ прямо разрешено распространять базу в продукте;
- IPinfo Lite — CC BY-SA 4.0, использование в продукте разрешено с атрибуцией;
- GeoLite2 EULA — старые версии нужно уничтожать в течение 30 дней после выхода новых.


Дата проверки: 4 ноября 2026 г. Цитаты приведены дословно, на английском, по официальным страницам провайдеров. URL указан рядом с каждой цитатой.

Пометки:
- **[НЕ ПРОВЕРЕНО]**: не удалось подтвердить по первоисточнику. Это общие знания, сторонний источник или вывод автора.
- **[ВЫВОД]**: инженерная или юридическая интерпретация автора, а не текст провайдера.

Это не юридическое заключение. Перед релизом стоит перечитать условия: MaxMind, ipinfo, ipapi.is и ipwhois.io меняли их в 2026 г.

---

## 0. Главное

1. **Базовая БД в нашем подписанном релизе (a).** Юридически чисто подходят только открытые наборы:
   - **DB-IP Lite** (CC BY 4.0);
   - **iptoasn.com** (PDDL, public domain);
   - **IPinfo Lite** (CC BY-SA 4.0);
   - дополнительно IPLocate (CC BY-SA 4.0).

   Не подходят: **MaxMind GeoLite2**, **IP2Location LITE**, **CAIDA pfx2as** и **RIPEstat**. Для MaxMind нужна платная лицензия на редистрибуцию, плюс есть обязанность уничтожать старые копии в течение 30 дней. У IP2Location формулировки противоречат друг другу. У CAIDA нет права на редистрибуцию, у RIPEstat она прямо запрещена.
2. **У ipinfo открытая БД есть.** Мнение владельца не подтвердилось. **IPinfo Lite** скачивается в MMDB, CSV, JSON и Parquet, лицензия CC BY-SA 4.0, а FAQ прямо разрешает использование «within a product». Для скачивания нужен бесплатный аккаунт и токен. Сохранились и прежние бесплатные `country_asn` / `asn` / `country`.
3. **БД, которую оператор импортирует сам (b):**
   - MaxMind GeoLite2 ASN + Country по ключу оператора, с обязанностью обновлять или уничтожать копию за 30 дней;
   - IPinfo Lite по токену оператора;
   - IP2Location LITE по токену оператора;
   - платные БД.
4. **Онлайн-API (c).** Условия по приватности сильно различаются:
   - **ipapi.is** прямо пишет, что не логирует запрошенные IP;
   - **ip2location.io** хранит запрошенные IP **2 года**;
   - **ipapi.co** пишет их в логи;
   - бесплатный **ip-api.com** работает только по HTTP и только для некоммерческого использования;
   - у ipinfo, ipwho.is, Team Cymru и RIPEstat про логирование запрошенных IP ничего не сказано.

---

## 1. Сводная таблица

Сокращения: «Н/П» — не применимо; «нет данных» — провайдер об этом ничего не пишет.

| Источник | Данные | Формат / размер / обновление | Доступ | Лицензия | Можно класть в наш релиз? | Атрибуция | API: логи / кэш / лимиты |
|---|---|---|---|---|---|---|---|
| **MaxMind GeoLite2 ASN + Country** | ASN, AS org; страна (ISO) | MMDB, CSV. Размер ~8–10 МБ на файл **[НЕ ПРОВЕРЕНО]**. ASN обновляется каждый будний день, Country — по вторникам и пятницам | Аккаунт и license key, не более 30 скачиваний в сутки | GeoLite EULA (ред. 12.02.2026); на «copyrightable elements» действует CC BY-SA 4.0 | **Нет.** По KB MaxMind нужна Commercial Redistribution License (от $5 000 за базу). Старые копии нужно уничтожать в течение 30 дней. Свои обязательства нужно передавать получателям | Обязательна. Пример: «This product includes GeoLite Data created by MaxMind…» | Веб-сервис GeoLite: 1000 запросов в сутки на сервис. Логи: нет данных |
| **IPinfo Lite (БД)** | network, ASN, AS name, AS domain, страна, континент | MMDB 24,84 МБ; CSV.gz 25,5 МБ; JSON; Parquet. Обновление ежедневно | Бесплатный аккаунт и токен | **CC BY-SA 4.0** | **Да.** Нужна атрибуция; изменённая БД распространяется под CC BY-SA. Для CI нужен токен | Обязательна: ссылка на ipinfo.io | См. строку «ipinfo API» |
| **IP2Location LITE ASN + DB1** | ASN LITE: диапазон, CIDR, ASN, AS name. DB1: страна | BIN, CSV, MMDB. ASN (IPv4): MMDB 10,8 МБ, CSV 110 МБ. DB1 (IPv4): BIN 2,8 МБ, MMDB 15 МБ. Обновление 1–2 раза в месяц | Бесплатный аккаунт и download token | Собственная «Data License». На странице DB1 есть бейдж CC BY-SA 4.0, на странице ASN его нет — формулировки **противоречивы** | **Скорее нет.** Data License: «not permitted to redistribute». FAQ: «one copy… with attribution», пользователи должны регистрироваться, «third party database repository is not allowed» | Обязательна, текст фиксирован | Н/П |
| **DB-IP Lite: IP-to-ASN + IP-to-Country** | ASN Lite: диапазон, ASN, AS org. Country Lite: диапазон, страна, континент, членство в ЕС | CSV, MMDB. ASN: MMDB 9,2 МБ, CSV 29,4 МБ. Country: MMDB 8,1 МБ, CSV 31 МБ. Обновление ежемесячно | Аккаунт не нужен, достаточно отметить согласие с лицензией | **CC BY 4.0** | **Да.** FAQ прямо разрешает «redistribute» | Обязательна; в веб-интерфейсе нужна ссылка на db-ip.com | Н/П |
| **iptoasn.com** | диапазон, ASN, страна, AS description. Отдельно есть файлы ip→country | TSV.gz; combined ≈ 11 МБ gz. Заявлено «Updated hourly», но на 04.11 все файлы датированы 01.11.2026 | Аккаунт не нужен | **PDDL 1.0** (public domain) | **Да, без условий** | Не требуется | Публичный API закрыт с 31.12.2020 |
| IPLocate (доп. вариант) | ASN, AS name, org, domain; страна | CSV, MMDB. ip-to-asn.mmdb 76 МБ, CSV 12 МБ. Обновление ежедневно | Без регистрации, есть зеркало на GitHub | CC BY-SA 4.0 | Да, при соблюдении атрибуции и ShareAlike | Обязательна | Н/П |
| **CAIDA pfx2as (RouteViews)** | prefix, длина, origin AS (в том числе MOAS и AS-set). **Нет имён AS и стран** | TSV.gz, ≈ 4 МБ в сутки (IPv4). Обновление ежедневно | Аккаунт не нужен | CAIDA AUA для публичных датасетов | **Нет явного права.** Лицензия даёт только «copy, modify, and use» | Цитирование в публикациях | Н/П |
| RouteViews (сырые MRT/RIB) | BGP-таблицы | MRT, большие объёмы | Открыто | **CC BY 4.0** | Да: собственную производную карту prefix→AS можно распространять с атрибуцией | «This [Product] utilizes data provided by RouteViews…» | Н/П |
| **RIR delegated-extended (NRO)** | Только **страна регистрации держателя** (cc) для диапазонов и ASN, плюс opaque-id. Имён AS нет | Текст с разделителем `\|`. Обновление ежедневно | Открыто («world-readable») | Явной лицензии нет. APNIC: «freely available for download and use» | Вероятно да, это факты, но явного разрешения нет **[НЕ ПРОВЕРЕНО полностью]** | Не требуется явно | Н/П |
| **Team Cymru IP→ASN** | ASN, BGP prefix, cc, RIR, дата, AS name | DNS TXT, whois (TCP 43), HTTPS-форма. Обновление каждые 4 ч | Ключ не нужен | ToS и privacy policy **не найдены** (страница privacy-policy отдаёт 404); заявлено «Free, forever» | Н/П | — | Логи: **нет данных**. DNS и whois идут открытым текстом. За «hammering» — null route |
| **RIPEstat Data API** | prefix, ASN, holder и др. | JSON по HTTPS | Ключ не нужен. При >1000 запросов в день просят зарегистрироваться; не более 8 параллельных запросов с одного IP | RIPEstat T&C | **Нет.** Ст. 3.3: «may not re-package, compile, re-distribute» | Атрибуция при публикации исследований | Логи: **нет данных**. Коммерческое использование — только с письменного разрешения |
| **ip-api.com (free)** | ASN/org, ISP, страна и др. | JSON, **только HTTP** | Ключ не нужен | ToS ip-api.com | Н/П | — | «We do not log requests»; IP клиента держат в RAM до 1 минуты. 45 запросов в минуту. **Только некоммерческое использование** |
| **ipapi.co (free)** | ASN, org, страна и др. | JSON по HTTPS | Ключ не нужен | ToS ipapi.co | Н/П | — | **«IP queries stored in logs»**. 30 000 запросов в месяц, не более 1000 в день. «Not for production use». Данные только для внутреннего использования |
| **ipapi.is (free)** | ASN, org, страна, признаки хостинга, VPN и др. | JSON по HTTPS | Аккаунт и API key; есть урезанный анонимный уровень | ToS ipapi.is (ред. 03.10.2026) | Н/П | — | **«We do NOT log or store: IP addresses from API queries»**. 1000 запросов в день, коммерческое использование разрешено. Кэш — не дольше 30 дней |
| **ipwho.is (free)** | connection.asn, org, isp, страна | JSON, HTTPS поддерживается | Ключ не нужен | ToS ipwhois.io (ред. 21.05.2026) | Н/П | — | Логи API: **нет данных**. 1000 запросов в день на IP клиента. «Commercial use allowed». Про кэш ничего не сказано |
| **ipinfo API (Lite)** | ASN, AS name, domain, страна | JSON по HTTPS | Токен | ToS ipinfo; данные Lite — CC BY-SA 4.0 | Н/П | Обязательна | Объём: «Unlimited». Логи запрошенных IP: в privacy policy **не указано**. Про кэш ничего не сказано |
| **ip2location.io** | ASN, AS, страна и др. | JSON по HTTPS | Без ключа — 1000 запросов в день; бесплатный план с ключом — 50 000 в месяц | ToS ip2location.io v1.1 | Н/П | Обязательна на бесплатном и бесключевом доступе | **Запрошенные IP хранят 2 года**. Кэш — не дольше 30 дней; после прекращения договора удалить за 7 дней |

---

## 2. Подробности по каждому источнику

### 2.1 MaxMind GeoLite2 ASN / Country
Источники: https://www.maxmind.com/en/geolite2/eula (ред. «February 12, 2026»), https://dev.maxmind.com/geoip/geolite2-free-geolocation-data, https://support.maxmind.com/hc/en-us/articles/4408928143643, https://support.maxmind.com/knowledge-base/articles/download-and-update-maxmind-databases

- **Две лицензии сразу.** EULA §3: «to the extent the Services contain any copyrightable elements those copyrightable elements are governed by the Creative Commons License» (CC BY-SA 4.0). Для внутреннего использования EULA добавляет: «a non-exclusive, non-transferable limited license to access and use the Services for your own internal business purposes».
- **Передача третьим лицам**, EULA §6:
  - «Except as explicitly permitted by the Creative Commons License, you will not disclose the Services to any third party without notifying MaxMind of the anticipated disclosure and obtaining MaxMind's prior written consent»;
  - получателю нужно передать «the same or substantially similar contractual duties».

  Позиция MaxMind в KB однозначна: «If you would like to include data from MaxMind's GeoLite databases in a product or service you provide to your users or customers, you will need a Commercial Redistribution License for GeoLite». Эта лицензия обязывает связать пользователей EULA с ограничением «Internal Restricted Business Purposes». Цена — $5 000 за ASN и столько же за Country на один продукт в год (https://www.maxmind.com/en/commercial-geolite-license).
  - **[ВЫВОД]** Ссылка на CC BY-SA в §6 формально оставляет лазейку. Но сами факты IP→ASN, скорее всего, не охраняются авторским правом, поэтому CC ничего не даёт, а договорные §6 и KB MaxMind прямо требуют платную лицензию. Для публичного релиза на GitHub это **нельзя**.
- **Обязанность обновлять и уничтожать**, EULA §6: «You shall cease use of and destroy (i) any old versions of the Services within thirty (30) days following the release of the updated GeoLite Databases; and (ii) all Services immediately upon termination». На dev-портале: «you must delete GeoLite databases within 30 days of a new release».
  - **[ВЫВОД]** Это несовместимо с неизменяемыми подписанными архивами на GitHub: старые релизы продолжали бы раздавать устаревшие копии. Несовместимо это и с правилом «узел сам не ходит к третьим сторонам»: оператору пришлось бы вручную обновлять базу не реже раза в 30 дней.
- **Атрибуция и ограничения.** §3 требует: «You must provide attribution of your use to MaxMind (an example of attribution: "This product includes GeoLite Data created by MaxMind, available from https://www.maxmind.com")». §5 запрещает использовать данные «for the purpose of identifying or locating a specific household, individual, or street address». §4 запрещает цели FCRA. По §9 MaxMind может прекратить бесплатную раздачу, по §10 — расторгнуть соглашение уведомлением.
- **Доступ и частота.** Нужны аккаунт и license key. KB: «limited to 1,000 total direct downloads (30 for GeoLite accounts) in a 24-hour period». ASN обновляется «Every weekday (Monday through Friday)», Country — «Every Tuesday and Friday». Веб-сервис: «limited to 1000 lookups per day per service».

### 2.2 ipinfo: IPinfo Lite (БД)
Источники: https://ipinfo.io/lite, https://ipinfo.io/developers/ipinfo-lite-database, https://community.ipinfo.io/t/ipinfo-lite-faq/6768, https://ipinfo.io/terms-of-service

- **Открытая БД существует.** Страница разработчика: «Our IPinfo Lite data downloads service is released under Creative Commons Attribution-ShareAlike 4.0 International License». Скачивание: `curl -L https://ipinfo.io/data/ipinfo_lite.mmdb?token=$TOKEN`. Файлы на 03.11.2026: MMDB 24,84 МБ, CSV.gz 25,52 МБ, 4 385 997 строк. Поля: `network, country, country_code, continent, continent_code, asn, as_name, as_domain`.
- **Использование в продукте разрешено**, FAQ на /lite: «Can I use IPinfo Lite data within a product? Yes … IPinfo Lite is released under the Creative Commons Attribution-ShareAlike 4.0 International License, which allows you to freely use and incorporate the data into commercial and non-commercial applications. The only requirement is that you provide attribution to IPinfo as your data source.» Обновление: «Data updates every 24 hours».
- **Старые бесплатные БД.** На той же странице остались `https://ipinfo.io/data/free/country_asn.mmdb?token=…`, `asn.mmdb` и `country.mmdb`. Community FAQ от 01.05.2025: Lite «is the evolution of our previous free IP to Country ASN database».
- **Условия CC BY-SA 4.0** (legalcode §3(a), 3(b), 2(a)(5)(B)) для того, что кладётся в релиз:
  - сохранить атрибуцию и ссылку на лицензию;
  - «indicate if You modified the Licensed Material»;
  - изменённую БД (урезанную, конвертированную) распространять под «a Creative Commons license with the same License Elements»;
  - «You may not offer or impose any additional or different terms».
  - **[ВЫВОД]** ShareAlike касается самой БД, а не кода raycontrol, если БД лежит рядом отдельным файлом. Подпись архива не является «Effective Technological Measure», которая ограничивала бы права получателя.
- **Оговорка.** Общие ToS ipinfo говорят: «You can use content obtained from the Site for your internal business purposes. However, selling or reselling this content is strictly prohibited without IPinfo's written consent». Для данных Lite действует явная CC-лицензия и FAQ «within a product», а мы ничего не продаём. Тем не менее формулировки расходятся **[ВЫВОД]**. Токен для CI выдаётся через аккаунт, его нельзя публиковать.

### 2.3 IP2Location LITE (ASN LITE, DB1)
Источники: https://lite.ip2location.com/data-license, https://lite.ip2location.com/faqs, https://lite.ip2location.com/database/ip-asn, https://lite.ip2location.com/database/ip-country, https://www.ip2location.com/database/lite

- **Data License противоречит сама себе.** Пункт 2: «You are not permitted to redistribute or resell this product». Пункт 5: «Licensees may copy, distribute, display, and perform the work and create derivative works based on IP2Location LITE only if they give IP2LOCATION.COM credits». На странице DB1 стоит бейдж `rel="license"` CC BY-SA 4.0, на странице ASN LITE его нет.
- **FAQ о редистрибуции:** «You can redistribute one copy of the LITE database with your application with attribution. However, you need to inform all users to register for an individual license in https://lite.ip2location.com to download updates. Third party database repository is not allowed.» **[ВЫВОД]** Публичный GitHub Release с тысячами скачиваний плохо сочетается с «one copy» и запретом «third party database repository». Риск высокий.
- **Атрибуция фиксированная.** Для DB1: «[Your site name or product name] uses the IP2Location LITE database for <a href="https://www.ip2location.com">IP geolocation</a>». Для ASN: «[Product Name] uses the IP2Location ASN LITE database for … autonomous system lookup».
- **Доступ и обновления.**
  - Нужен аккаунт; скачивание по токену, например `./download.pl -package DB11LITE -token DOWNLOAD_TOKEN`. FAQ предупреждает: «We will disable any LITE account if account sharing or massive download is detected».
  - Скачивание перенесено на https://www.ip2location.com/database/lite, там указано «Update Frequency: Semi-monthly». В FAQ: «We update … on the first day of the calendar month». Страница DB1 показывает «Current Version 01 November, 2026 / Next Update 15 November, 2026».
- **Размеры.**
  - ASN LITE IPv4: BIN 161 МБ, CSV 110,5 МБ, MMDB 10,76 МБ.
  - ASN LITE IPv6: BIN 270 МБ, CSV 112,7 МБ.
  - DB1 IPv4: BIN 2,76 МБ, CSV 13,8 МБ, MMDB 15,13 МБ.
  - Платная «Master License Agreement» (https://lite.ip2location.com/terms-of-use) Standard/Site прямо пишет: «Redistribution to third parties is strictly prohibited».

### 2.4 DB-IP Lite (ip-to-asn-lite, ip-to-country-lite)
Источники: https://db-ip.com/db/download/ip-to-asn-lite, https://db-ip.com/db/download/ip-to-country-lite, https://db-ip.com/db/lite.php, https://db-ip.com/faq.php

- **Лицензия:** «The free IP to ASN Lite database by DB-IP is licensed under a Creative Commons Attribution 4.0 International License. You are free to use this IP to ASN Lite database in your application, provided you give attribution to DB-IP.com for the data.»
- **Веб-интерфейс:** «In the case of a web application, you must include a link back to DB-IP.com on pages that display or use results from the database». Готовый фрагмент: `<a href='https://db-ip.com'>IP Geolocation by DB-IP</a>`.
- **Редистрибуция прямо разрешена** (FAQ): «Our free database downloads are licensed under a Creative Commons license, you are allowed to use the database in a commercial product and redistribute it as long as you comply with the rest of the licensing terms.»
- **Формат и частота:** «updated monthly and available in CSV and MMDB formats».
  - ASN Lite (релиз November 2026): 485 292 записи, MMDB 9,2 МБ. Поля: First IP, Last IP, AS number, AS organization.
  - Country Lite: 732 796 записей, MMDB 8,1 МБ. Поля: континент, страна ISO alpha-2, членство в ЕС, название страны.
  - Аккаунт не нужен, только отметка «I agree with the licensing terms».
- **Качество:** «a subset of the IP to ISP database with reduced coverage and accuracy».

### 2.5 iptoasn.com
Источники: https://iptoasn.com/, https://opendatacommons.org/licenses/pddl/1-0/

- **Лицензия:** в подвале сайта «Licensed under Public Domain (PDDL v1.0)». PDDL §3.1: «dedicates the Work to the public domain for the benefit of the public and relinquishes all rights in Copyright and Database Rights over the Work». Community Norms юридически не обязывают. Кладём в релиз без условий.
- **Файлы:** `ip2asn-combined.tsv.gz` (IPv4 и IPv6), `ip2asn-v4.tsv.gz`, `ip2asn-v6.tsv.gz`, `ip2country-v4/v6.tsv.gz`. Формат строки: «range_start range_end AS_number country_code AS_description». Combined весит 10,96 МБ в gz.
- **Частота:** на сайте написано «Updated hourly». Но при проверке 04.11.2026 у всех файлов `Last-Modified: Sun, 01 Nov 2026`, то есть часовое обновление не подтвердилось.
- **API нет:** «The public API was phased out on December 31, 2020 due to increasing traffic». Код сервера открыт: https://github.com/jedisct1/iptoasn-webservice. Проект ведёт один человек, Frank Denis.
- **Происхождение данных на сайте не описано [НЕ ПРОВЕРЕНО].** По общим сведениям это BGP-таблицы плюс данные RIR. Что означает `country_code` — страну регистрации в RIR или геолокацию — тоже не проверено.

### 2.6 IPLocate (дополнительный вариант, в исходном списке не было)
Источник: https://iplocate.io/free-databases

- «Everything is open and offline-ready under CC BY-SA 4.0». FAQ: «You're free to use, modify, and redistribute the data … as long as attribution is provided and derivatives are shared under the same license».
- Регистрация не нужна, есть зеркало https://github.com/iplocate/ip-address-databases. Обновление ежедневное; GitHub-зеркало может отставать.
- Размер великоват для базовой БД: ip-to-asn.mmdb 76,4 МБ, ip-to-country.mmdb 16,7 МБ.

### 2.7 CAIDA RouteViews prefix2as (pfx2as) и сами данные RouteViews
Источники: https://www.caida.org/catalog/datasets/routeviews-prefix2as/, https://www.caida.org/about/legal/aua/public_aua/, https://publicdata.caida.org/datasets/routing/routeviews-prefix2as/README.txt, https://www.routeviews.org/routeviews/licenses/

- **Происхождение pfx2as:** «Files are generated with straightenRV using a single BGP table snapshot (that is, a RIB file) provided by RouteViews». Формат: «IP prefix, prefix length, AS», где AS бывает multi-origin (`10_20`) или AS-set (`32,54`). Последний файл IPv4 — `routeviews-rv2-20261102-1200.pfx2as.gz`, ≈ 4 МБ. Имён AS и стран нет.
- **Лицензия CAIDA AUA:** «a limited, non-exclusive, non-transferable, non-assignable, and terminable license to copy, modify, and use the data» и «No license is granted for any other purpose and there are no implied licenses in this Agreement». Права на редистрибуцию нет, поэтому для (a) не подходит. Требования: цитирование «The CAIDA UCSD [Dataset Name] - [dates used]» и сообщение CAIDA о публикациях.
- **Сами данные RouteViews:** «Use of the data created and owned by RouteViews ("RouteViews Data") is licensed under a Creative Commons Attribution 4.0 International License».
  - Для продуктов просят атрибуцию: «This [Product/Report] utilizes data provided by RouteViews (www.routeviews.org)».
  - Лицензию могут отозвать: «RouteViews and University of Oregon may revoke your license … at any time», если нет атрибуции или есть злоупотребление.
  - **[ВЫВОД]** Можно в CI самим строить карту prefix→origin AS из MRT/RIB RouteViews и класть её в релиз с атрибуцией. Но имён AS и стран там не будет.

### 2.8 RIR delegated-extended statistics (только страна)
Источники: https://www.nro.net/about/rirs/statistics/, https://ftp.ripe.net/pub/stats/ripencc/RIR-Statistics-Exchange-Format.txt, https://ftp.apnic.net/stats/apnic/README.TXT, https://www.arin.net/reference/research/statistics/nro_stats/

- **Смысл поля страны:** «The cc value identifies the country in which the resource holder is legally based. However, it is not specified whether this is the country where the IP addresses are used. This value can therefore not be reliably used to map IP addresses to countries.» То есть это **страна регистрации держателя**, а не страна сети.
- **Доступность:** «Data will be publicly visible and will not require access control (world-readable)». Файлы ежедневные. Сводный файл NRO: https://ftp.ripe.net/pub/stats/ripencc/nro-stats/latest/nro-delegated-stats. Формат: `registry|cc|type|start|value|date|status|opaque-id`.
- **Условия:**
  - APNIC: «The files are freely available for download and use on the condition that APNIC will not be held responsible for any loss or damage arising from the use of the information contained in these reports».
  - У NRO и ARIN лицензия на странице не указана. У ARIN в шапке есть ссылка на Whois ToU, но она касается Whois, а не статистики.
  - **[НЕ ПРОВЕРЕНО]** Явного разрешения на редистрибуцию не нашлось. Риск низкий, потому что это публикуемые факты.

### 2.9 Team Cymru IP→ASN (DNS / whois)
Источник: https://www.team-cymru.com/ip-asn-mapping

- «Free, forever. Underwritten by Team Cymru as a community service». Возвращает ASN, BGP prefix, cc, registry, дату выделения и AS name.
- О данных: «Every interface reads from the same BGP feeds, drawn from more than 50 BGP peers and updated at four hour intervals… AS descriptions come from cidr-report».
- Лимиты: «IPs that hammer the whois server with large numbers of individual queries are null routed». Для регулярных запросов рекомендуют bulk-режим или DNS.
- **ToS, AUP и политика логирования не найдены**: https://www.team-cymru.com/privacy-policy отдаёт 404. **[НЕ ПРОВЕРЕНО]**
- **[ВЫВОД]** Интерфейсы DNS (`<reversed-ip>.origin.asn.cymru.com`) и whois (TCP 43) открыты: запрошенный IP видят резолвер и все промежуточные узлы. Для IP клиентов VPN это неприемлемо.

### 2.10 RIPEstat Data API
Источники: https://www.ripe.net/about-us/legal/ripestat-service-terms-and-conditions/, https://stat.ripe.net/docs/data_api

- **Назначение**, ст. 3.1: «for purposes such as network analysis, network monitoring and debugging and research».
- **Запреты**, ст. 3.3: «A User may not re-package, compile, re-distribute the RIPEstat Service and any (or all) of the RIPEstat Data. Use of the RIPEstat Service for commercial purposes … is not allowed unless permission to do so is granted in writing by the RIPE NCC». Право ограничить доступ — ст. 4.2.
- **Лимиты:** «No limit on the amount of requests»; «please register if you plan to regularly do more than 1000 requests/day»; «limits the usage to 8 concurrent … requests coming from one IP address». Рекомендован параметр `sourceapp`.
- **Логирование и хранение запросов** ни в T&C, ни в найденной части privacy statement RIPE NCC не описаны. **[НЕ ПРОВЕРЕНО]**

### 2.11 ip-api.com (бесплатный)
Источники: https://ip-api.com/docs/legal, https://ip-api.com/docs/api:json

- **Логи:** «To protect and rate-limit the API we store the network IP address of your client in memory (RAM) for up to 1 minute. Any other information you provide is discarded after your request is answered. We do not log requests.»
- **Только некоммерческое использование:** «The use of the API is strictly limited for a non-commercial purpose and in a non-commercial environment… Only members with a pro subscription can use the API in a commercial environment».
- **Нет TLS:** «256-bit SSL encryption is not available for this free API». Лимит: «45 requests per minute», при превышении HTTP 429, затем бан на час.
- Про хранение и кэширование результатов ничего не сказано. Источники данных: «For some IP ranges we fallback to GeoLite2 data created by MaxMind».

### 2.12 ipapi.co
Источники: https://ipapi.co/pricing/, https://ipapi.co/privacy/, https://ipapi.co/terms/

- **Бесплатный тариф:** 30 000 запросов в месяц, не больше 1000 в день, «Suitable for testing / development», «**Not for production use**».
- **Запросы логируются:** «IP queries stored in logs (your data is still safe)». В privacy policy: «We do not share or sell your IP address queries. They get stored in log files for a limited time, like any standard webserver logs». Отключить логирование можно только на платных тарифах: «Contact us to bypass IP query logging».
- **ToS:** «Under no circumstances are you permitted to resell or license the Content. Your use of the Content is limited to your internal use and the internal use of your Clients».

### 2.13 ipapi.is
Источники: https://ipapi.is/privacy.html, https://ipapi.is/terms.html (ред. «3rd October 2026»), https://ipapi.is/pricing.html, https://ipapi.is/geolocation.html

- **Логов запрошенных IP нет**, privacy policy §3.3/§6: «We do NOT log or store: IP addresses from API queries; Individual API request details or queried data». Веб-логи сайта хранятся 14 дней.
- **Бесплатный тариф**, §2.9: «Every registered account includes a free tier of 1,000 API requests per day. The free tier requires an account and an API key… It is not a trial… and it is not restricted to testing, development or non-commercial use».
- **Кэш и хранение:**
  - §2.2: «Caching API query results for up to 30 days solely for resiliency or performance reasons, after which the data must be refreshed or deleted»;
  - §2.2: «Any derived metrics … must irreversibly transform the data so that a third party cannot reconstruct more than a negligible portion»;
  - §2.5: «Results that have become part of your own records of individual events, such as a log entry… may be kept».
  - После окончания договора всё нужно удалить в течение 30 дней.
- **Ограничение §1.2:** «our databases and API data are licensed, not sold, for your own internal use only». **[ВЫВОД]** Счётчики, агрегированные по ASN, подходят под «derived metrics». Но публиковать имена AS, полученные от ipapi.is, в публичных отчётах рискованно.
- **Отдельно:** бесплатная БД геолокации ipapi.is (CSV 559 МБ) лицензирована CC BY-SA 4.0 и строится только по WHOIS. ASN в ней нет, поэтому для нас она не нужна.

### 2.14 ipwho.is / ipwhois.io
Источники: https://ipwhois.io/pricing, https://ipwhois.io/documentation, https://ipwhois.io/terms (ред. 21.05.2026), https://ipwhois.io/privacy (ред. 18.01.2026)

- **Бесплатный тариф:** «No signup, no API key required», «1,000 requests / day», «Commercial use allowed». В документации: «The Free endpoint is limited to 1,000 requests per day per client IP address». HTTPS поддерживается.
- **ToS §2:** право использовать «for your personal or internal business purposes». Запрещено «copy, modify, resell, sublicense, or redistribute our materials or services without our prior written permission».
- **Privacy:** описаны только логи посещений сайта («Usage data is collected when you visit and use the Website, and may be stored in log files»). Про запрошенные через API IP ничего не сказано **[НЕ ПРОВЕРЕНО]**. Сервис работает через Cloudflare. Про хранение и кэш результатов тоже ничего.

### 2.15 ipinfo API
Источники: https://ipinfo.io/lite, https://ipinfo.io/pricing, https://ipinfo.io/privacy-policy (ред. «Effective: 29 October 2026»), https://ipinfo.io/terms-of-service

- **Lite API:** «Entirely free and without usage limits». В тарифах: Lite стоит $0, запросов «Unlimited», только данные уровня страны и ASN. Нужен токен; атрибуция обязательна («Attribution required»).
- **Логи:** privacy policy не говорит, записываются ли запрошенные через API IP **[НЕ ПРОВЕРЕНО]**. Есть только общая фраза: «We will keep your Information for as long as it remains necessary for the identified purpose». Для данных из приложения и SDK ipinfo пишет, что использует их «to build and improve IPinfo's IP address data products». **[ВЫВОД]** ipinfo — компания, которая торгует IP-данными. Без явного обещания не логировать исходим из того, что запросы могут сохраняться.
- **Кэш и хранение результатов** в ToS не описаны. ToS разрешают «internal business purposes».

### 2.16 ip2location.io
Источники: https://www.ip2location.io/terms-of-service (v1.1), https://www.ip2location.io/privacy-policy, https://www.ip2location.io/ip2location-documentation, https://www.ip2location.io/pricing

- **Запрошенные IP хранятся 2 года:** «Query Data: To provide usage history, prevent API abuse, and maintain service security, we retain the input IP addresses from your API queries for a period of two (2) years».
- **Лимиты:** «up to 1,000 queries per day without the need to sign up for an API key (keyless)». Бесплатный план с ключом даёт «up to 50,000 queries per month». На бесплатном и бесключевом доступе атрибуция обязательна.
- **Кэш:** «Cached Data must not be retained for more than thirty (30) consecutive calendar days from the original query timestamp». После прекращения договора: «permanently delete and purge all cached API Data … within seven (7) calendar days».
- **Ключ:** запрещено «embed API keys in publicly accessible environments». Ключ оператора нельзя класть в открытый конфиг.

---

## 3. Рекомендации

### (a) Базовая БД внутри подписанного релиза
**Рекомендация: DB-IP IP-to-ASN Lite + DB-IP IP-to-Country Lite (MMDB, CC BY 4.0).**
- Готовый MMDB, примерно 9,2 + 8,1 МБ.
- Аккаунт не нужен, поэтому CI не требует секретов.
- Лицензия без ShareAlike, а FAQ прямо разрешает редистрибуцию в продукте.
- Нет обязанности обновлять или удалять старые копии, так что старые релизы на GitHub лицензию не нарушают.
- Обязательства:
  - файл `THIRD_PARTY_NOTICES` с текстом «IP Geolocation by DB-IP», ссылкой на https://db-ip.com и на CC BY 4.0;
  - ссылка на db-ip.com на страницах UI, где показываются результаты по ASN или стране;
  - если БД урезается или конвертируется, это нужно указать.
- Недостатки: обновление раз в месяц и формулировка «reduced coverage and accuracy».

Альтернативы:
- **iptoasn.com** (PDDL): никаких юридических обязательств. ASN, страна и AS description лежат в одном файле, ≈ 11 МБ gz. Его нужно конвертировать в CI в наш формат или в MMDB. Минусы:
  - проект держит один человек;
  - происхождение данных и смысл `country_code` не описаны **[НЕ ПРОВЕРЕНО]**;
  - заявленное часовое обновление не подтвердилось.
- **IPinfo Lite** (CC BY-SA 4.0): вероятно, лучшее качество (ежедневно; ASN, AS name, AS domain и страна в одном MMDB на 24,8 МБ). Цена:
  - в CI нужен токен ipinfo (секрет);
  - урезанная или конвертированная БД распространяется только под CC BY-SA 4.0 (на код raycontrol это не влияет **[ВЫВОД]**);
  - формулировки общих ToS ipinfo («internal business purposes», «reselling… prohibited») не совсем сходятся с CC.
- **Не использовать для (a):**
  - MaxMind GeoLite2: нужна Commercial Redistribution License, есть 30-дневное уничтожение копий и передача обязательств;
  - IP2Location LITE: противоречивые условия, «not permitted to redistribute» и «third party database repository is not allowed»;
  - CAIDA pfx2as: нет права на редистрибуцию;
  - RIPEstat: ст. 3.3.
- **Страна из RIR delegated-stats:** допустима только как явно подписанная «страна регистрации держателя», не как страна сети.

### (b) Более полная БД, которую оператор импортирует сам
Узел должен уметь импортировать **MMDB**. Этот формат есть у MaxMind, ipinfo, DB-IP, IP2Location и IPLocate. Нужен один ридер и сопоставление полей для каждого поставщика:
- в ipinfo Lite поле `asn` — строка вида `"AS13335"`, рядом `as_name`, `as_domain`, `country_code` (проверено по документации);
- в GeoLite2-ASN поля `autonomous_system_number` и `autonomous_system_organization` **[по памяти, не перепроверено]**.

Поддерживаемые варианты:
1. **MaxMind GeoLite2-ASN + GeoLite2-Country** по аккаунту и license key оператора. Лицензиат — оператор, использование — его «internal business purposes».
   - Обязанность обновлять и уничтожать копию за 30 дней лежит на операторе. Узлу стоит показывать возраст БД (`build_epoch` из метаданных MMDB) и предупреждать, если ей больше ~30 дней. Автоматически качать её узел не должен, это наше требование.
   - В UI нужна атрибуция MaxMind.
   - Показ имён AS из GeoLite посторонним (например, публичный отчёт) — неясная зона из-за §6 EULA. Лучше держать данные агрегированными и с атрибуцией **[ВЫВОД]**.
2. **IPinfo Lite** по токену оператора. Обновляется ежедневно, CC BY-SA, обязанности удалять старые копии нет. Вероятно, это лучший бесплатный вариант для импорта.
3. **IP2Location LITE ASN + DB1** по токену оператора. Нужна атрибуция; FAQ просит обновлять базу ежемесячно, а не скачивать массово.
4. **Платные:**
   - MaxMind GeoIP2 ISP/ASN, DB-IP IP-to-ISP, тарифы ipinfo Core/Max;
   - БД ipapi.is: «internal use only»; superseded-версии удалять через 90 дней, при окончании подписки — за 30.

   Оператор сам отвечает за их условия.

### (c) Онлайн-API — только как явная опция оператора
Порядок предпочтения по опубликованным условиям:
1. **ipapi.is** — единственный, кто прямо обещает «We do NOT log or store: IP addresses from API queries». Плюс HTTPS, бесплатно 1000 запросов в день с коммерческим использованием, кэш до 30 дней.
2. **RIPEstat** — некоммерческий RIR. Но назначение ограничено «network analysis… research», данные нельзя передавать дальше, логирование не описано.
3. **ipinfo Lite API** — лимитов нет, HTTPS. Политика логирования запрошенных IP не опубликована.

Не рекомендуются:
- **ip2location.io** — хранит запрошенные IP 2 года;
- **ipapi.co** — пишет запросы в логи, бесплатный тариф «not for production»;
- **ip-api.com free** — только HTTP, IP идёт открытым текстом; только некоммерческое использование;
- **ipwho.is** — логирование не описано, сервис за Cloudflare;
- **Team Cymru** — DNS и whois открытым текстом, ToS и privacy policy нет.

**Предупреждение о приватности для (c).** Любой онлайн-запрос раскрывает третьей стороне две вещи: IP или сеть клиента и IP самого узла. По сути провайдер получает список сетей пользователей конкретного сервера обхода блокировок. Его логи могут быть изъяты или проданы. Даже «no logging» — это лишь заявление провайдера, проверить его нельзя. Если оператор всё же включает API, стоит применить меры **[ВЫВОД]**:
1. Отправлять не IP клиента, а адрес сети: `/24` для IPv4 (`a.b.c.0`) и `/48` для IPv6. BGP-префиксы длиннее /24 и /48 обычно фильтруются, так что ASN почти всегда совпадает. Это общепринятая практика, а не условие провайдера.
2. Кэшировать ответ на уровне префикса не дольше срока, разрешённого провайдером: 30 дней у ipapi.is и ip2location.io.
3. Ходить в API только при поступлении отчёта и только при промахе локальной БД. Никаких запросов по расписанию.
4. Предупредить пользователей: IP — это персональные данные, их передача третьей стороне должна быть описана в политике оператора.
5. Хранить API-ключ только в секретах узла (так требуют, например, ToS ip2location.io).

---

## 4. Что осталось неясным
- iptoasn.com: откуда берутся данные, что означает `country_code`, и почему файлы не обновлялись с 01.11.2026 при заявленном «Updated hourly».
- IP2Location LITE: что из противоречащих текстов считать действующим — «not permitted to redistribute», «one copy… with attribution» или бейдж CC BY-SA на DB1. Ответ можно получить только письменно у Hexasoft.
- MaxMind: как именно сочетаются CC BY-SA для «copyrightable elements» и §6 EULA при показе агрегатов третьим лицам. Ответ — только письменно у MaxMind (legal@maxmind.com).
- Логирование запрошенных IP у ipinfo API, ipwho.is, Team Cymru и RIPEstat в опубликованных документах не описано.
- Размеры MMDB у MaxMind GeoLite2 и имена полей GeoLite2 — по памяти.
- Лицензия RIR delegated-stats: явной лицензии у NRO, ARIN и RIPE NCC нет; у APNIC есть только условие об отказе от ответственности.
