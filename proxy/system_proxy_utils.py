import winreg
import ctypes

def set_windows_proxy(host, port):
    proxy = f"{host}:{port}"
    internet_settings = winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        0, winreg.KEY_SET_VALUE
    )
    winreg.SetValueEx(internet_settings, "ProxyEnable", 0, winreg.REG_DWORD, 1)
    winreg.SetValueEx(internet_settings, "ProxyServer", 0, winreg.REG_SZ, proxy)
    winreg.CloseKey(internet_settings)

    # 通知系统代理设置已更新
    INTERNET_OPTION_SETTINGS_CHANGED = 39
    INTERNET_OPTION_REFRESH = 37
    ctypes.windll.Wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
    ctypes.windll.Wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)
    print(f"[+] 已设置系统代理为 {proxy}")


def unset_windows_proxy():
    # 打开注册表项
    internet_settings = winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        0, winreg.KEY_SET_VALUE
    )

    # 设置 ProxyEnable = 0，禁用代理
    winreg.SetValueEx(internet_settings, "ProxyEnable", 0, winreg.REG_DWORD, 0)
    winreg.CloseKey(internet_settings)

    # 通知系统代理设置已更改
    INTERNET_OPTION_SETTINGS_CHANGED = 39
    INTERNET_OPTION_REFRESH = 37
    ctypes.windll.Wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
    ctypes.windll.Wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)
    print("[+] 系统代理已取消")