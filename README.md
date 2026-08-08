**NETPROBE**  
Диагностика сетевых блокировок: DNS, SNI, QUIC, MTU, перехват HTTPS.  
Один файл, только стандартная библиотека Python 3.7+. Ставить ничего не нужно.  
**netprobe ставит диагноз, а не обходит блокировки.** Он показывает, что именно и на каком уровне сломано, чтобы не чинить вслепую.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OMQ2AABAAsSPBCj5fFyM6mJHAjAU2QtIq6DIzW7UHAMBfnGt1V8fXEwAAXrsexOEF35f1aEgAAAAASUVORK5CYII=)  

**ЗАПУСК**  

**1. Сначала — самопроверка.** Проверяет сам скрипт, в сеть не выходит:  

python3 netprobe.py selftest  
   
норма везде — выводам можно доверять. недоступно — ограничение системы, не поломка. СБОЙ — ошибка скрипта, откройте issue с этим выводом.  

**2. Диагностика:**  

python3 netprobe.py client  
   
Для полной картины — два прогона и сравнение:  

python3 netprobe.py client --label novpn --json novpn.json   # VPN выключен  

python3 netprobe.py client --label vpn   --json vpn.json     # VPN включён  
 
python3 netprobe.py compare novpn.json vpn.json  
   
Если резолвер находится внутри туннеля, укажите его в обоих прогонах: --dns 10.8.0.1  

**3. Карта фильтрации — что вообще режут в этой сети:**  

python3 netprobe.py scan  

python3 netprobe.py scan --list scan-list.txt --json scan.json  
   
39 имён в восьми группах: контроль, видео, мессенджеры, соцсети, шифрованный DNS, обходные пути, почта и облака, разное. Отвечает не на вопрос «почему у меня сломалось», а на вопрос «какая здесь политика фильтрации». Результат осмысленно сравнивать между людьми и городами.  
Свой список — текстовый файл: имя, через пробел подпись. ## начинает группу, # — комментарий. Кириллические домены (почта.рф) принимаются и переводятся в punycode автоматически. Включите в список хотя бы одно заведомо доступное имя, иначе тотальную блокировку не отличить от обрыва связи.  
В репозитории лежит готовый scan-list.txt — 84 имени в 12 группах. 

**Обезличенный выпуск для обмена с другими:**  
python3 netprobe.py scan --anon --region "Region" --json scan-2026-08-07.json  
   
--anon убирает внешний IP, адреса резолверов, локальные интерфейсы и пути с именем пользователя. Остаётся ASN сети, страна, указанный регион и результаты — достаточно, чтобы сравнивать замеры между сетями, недостаточно, чтобы указать на человека.  

**Сводка по нескольким выпускам:**  

python3 netprobe.py digest scan-*.json --json digest.json  
   
Показывает, что режется во всех замерах (общая политика), что только в части (местный фильтр, с указанием где), и долю блокировок по группам. Если контрольные имена не прошли ни в одном выпуске, сводка не строится: это признак обрыва связи, а не блокировки. 

**НА VPN-СЕРВЕРЕ:**  

sudo python3 netprobe.py server  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAM0lEQVR4nO3OUQmAQBBAwSdcjsu6HYxoDsEK/okwk2COmdnVGQAAf3GtalX76wkAAK/dDxFWBDkFf6+SAAAAAElFTkSuQmCC)  
**Что проверяет:**  

**1. DNS.** Перехват порта 53 (пробы по пяти несуществующим адресам), инъекция ответов, подмена NXDOMAIN, валидация DNSSEC, сверка открытого 53 с DoH, доступность DoH и DoT, блэкхол по фрагментации.  
**2. Транспорт.** Фильтрация по SNI с различением RST-инъекции и тихого дропа, карта охвата по девяти именам, блокировка по IP, QUIC через Version Negotiation, матрица портов, path MTU, устойчивость при повторных попытках.  
**3. HTTPS.** Подмена сертификата — антивирус с проверкой SSL, корпоративный прокси, чужой корневой сертификат. Страница-заглушка на 80-м порту.  
**4. Маршрутизация.** Идут ли трафик и DNS через туннель, утечка IPv6, состояние Частного DNS на Android.  
**5. Карта фильтрации (режим scan).** Реакция DPI на имя в ClientHello по группам сервисов, с контрольной группой и разбивкой «сколько из скольких» — видно политику, а не отдельный сломанный сайт.  
**6. Устойчивость.** Прогон переживает падение отдельного раздела и Ctrl+C: собранное сохраняется, вердикт выдаётся по неполным данным. Запись результата атомарна — оборванное сохранение не портит прежний файл.  
**7. Сервер.** Кто слушает :53, открытый наружу резолвер, рекурсия, выход наружу, правила файрвола, sniffing в XRay, MTU туннеля, ip_forward, таблица conntrack, расхождение часов.  
В конце отчёта — вердикт и блок «ЧТО ДЕЛАТЬ» с шагами в порядке важности.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANklEQVR4nO3OMQ2AABAAsSNBCkJfFSqwwIgHRiywEZJWQZeZ2ao9AAD+4lyruzq+ngAA8Nr1AOH8BeZxN/IIAAAAAElFTkSuQmCC)  

**Платформы**

| | |
|-|-|
| Linux | полностью |   
| Windows | winget install Python.Python.3.12, запуск через py |   
| Android | Termux с F-Droid, pkg install python; часть проверок маршрутизации недоступна |   
| Сервер | под sudo, иначе ss -p и iptables промолчат |   

   
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANElEQVR4nO3OQQmAABRAsSdYxKY/jMFMIZ7ECt5E2BJsmZmt2gMA4C+Otbqr8+sJAACvXQ85QgYXd/O+eQAAAABJRU5ErkJggg==)  

**Приватность**  
Скрипт ничего никуда не отправляет и работает только на вашей машине.  
Файлы --json содержат ваш внешний IP, адреса резолверов и внутренние подсети. **Не публикуйте их и не коммитьте в репозиторий.**  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANElEQVR4nO3OQQmAUBBAwSf8GGLWDWFDY3ixgjcRZhLMNjNHdQYAwF9cq1rV/vUEAIDX7gcRXAQ2s/16gwAAAABJRU5ErkJggg==)  

**Ограничения**  
Прогон client занимает около 40 секунд, scan — около 10 (полный список из 84 имён дольше), в сети с блокировками дольше — каждый таймаут до пяти секунд. Это не зависание.  
Отсутствие находок не доказывает отсутствие блокировок: фильтрация бывает плавающей и меняется в течение дня. Проверка устойчивости частично это ловит, но не полностью.  
Отсутствие результата и отсутствие блокировок — разные вещи, и скрипт их различает: при полном отказе сети выводится «ДАННЫХ НЕТ», а не «блокировок не найдено».  
Определение туннеля опирается на имена интерфейсов. Нестандартно названный адаптер может быть не опознан — тогда соответствующие строки помечаются как «не проверялось», а не как утечка.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANklEQVR4nO3OMQ2AABAAsSNBACP6MMH6NpGACyywEZJWQZeZ2aszAAD+4l6rrTq+ngAA8Nr1AL+6BElk4wV6AAAAAElFTkSuQmCC)  

**ЛИЦЕНЗИЯ**

MIT  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OMQ2AABAAsSPBCUZfEnoYmFDBhAU2QtIq6DIzW7UHAMBfnGt1V8fXEwAAXrse/wcF74lXkIsAAAAASUVORK5CYII=)  

