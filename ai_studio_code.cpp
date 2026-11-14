#define NOMINMAX
#include <windows.h>
#include <winhttp.h>
#include <objidl.h>
#include <gdiplus.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "PluginInterface.h"

namespace
{
    std::wstring Utf8ToWide(const std::string& utf8)
    {
        if (utf8.empty())
            return L"";
        int len = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), static_cast<int>(utf8.size()), nullptr, 0);
        if (len <= 0)
            return L"";
        std::wstring res(len, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), static_cast<int>(utf8.size()), &res[0], len);
        return res;
    }

    std::string ExtractJsonString(const std::string& json, const char* key)
    {
        std::string pattern = std::string("\"") + key + "\"";
        size_t pos = json.find(pattern);
        while (pos != std::string::npos)
        {
            size_t colon = json.find(':', pos + pattern.size());
            if (colon == std::string::npos)
                return "";
            size_t i = colon + 1;
            while (i < json.size() && (json[i] == ' ' || json[i] == '\t' || json[i] == '\r' || json[i] == '\n'))
                ++i;
            if (i >= json.size() || json[i] != '"')
                return "";

            ++i;
            std::string out;
            while (i < json.size())
            {
                char c = json[i++];
                if (c == '"')
                    return out;
                if (c == '\\' && i < json.size())
                {
                    char esc = json[i++];
                    switch (esc)
                    {
                    case '"': out.push_back('"'); break;
                    case '\\': out.push_back('\\'); break;
                    case '/': out.push_back('/'); break;
                    case 'n': out.push_back('\n'); break;
                    case 'r': out.push_back('\r'); break;
                    case 't': out.push_back('\t'); break;
                    case 'u':
                        if (i + 4 <= json.size())
                        {
                            unsigned int cp = 0;
                            bool ok = true;
                            for (int k = 0; k < 4; ++k)
                            {
                                char h = json[i + k];
                                cp <<= 4;
                                if (h >= '0' && h <= '9') cp |= (h - '0');
                                else if (h >= 'a' && h <= 'f') cp |= (h - 'a' + 10);
                                else if (h >= 'A' && h <= 'F') cp |= (h - 'A' + 10);
                                else { ok = false; break; }
                            }
                            if (ok)
                            {
                                i += 4;
                                if (cp < 0x80)
                                    out.push_back(static_cast<char>(cp));
                                else if (cp < 0x800)
                                {
                                    out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
                                    out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                                }
                                else
                                {
                                    out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
                                    out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                                    out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                                }
                            }
                        }
                        break;
                    default: out.push_back(esc); break;
                    }
                }
                else
                {
                    out.push_back(c);
                }
            }
            return out;
        }
        return "";
    }

    bool HttpGet(const wchar_t* host, INTERNET_PORT port, const wchar_t* path, bool useHttps, std::vector<uint8_t>& outBody)
    {
        outBody.clear();
        HINTERNET hSession = WinHttpOpen(L"TrafficMonitor-IPLocationRU/1.0",
                                         WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                         WINHTTP_NO_PROXY_NAME,
                                         WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession)
            return false;

        WinHttpSetTimeouts(hSession, 4000, 4000, 4000, 5000);

        HINTERNET hConnect = WinHttpConnect(hSession, host, port, 0);
        if (!hConnect)
        {
            WinHttpCloseHandle(hSession);
            return false;
        }

        DWORD flags = useHttps ? WINHTTP_FLAG_SECURE : 0;
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path, nullptr,
                                                WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
        if (!hRequest)
        {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }

        bool success = false;
        if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
            WinHttpReceiveResponse(hRequest, nullptr))
        {
            DWORD statusCode = 0;
            DWORD statusSize = sizeof(statusCode);
            if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                    WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX) &&
                statusCode >= 200 && statusCode < 300)
            {
                DWORD avail = 0;
                while (WinHttpQueryDataAvailable(hRequest, &avail) && avail > 0)
                {
                    size_t oldSize = outBody.size();
                    outBody.resize(oldSize + avail);
                    DWORD read = 0;
                    if (!WinHttpReadData(hRequest, outBody.data() + oldSize, avail, &read))
                    {
                        outBody.clear();
                        break;
                    }
                    outBody.resize(oldSize + read);
                }
                success = !outBody.empty();
            }
        }

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return success;
    }

    std::wstring FormatCurrentTime()
    {
        SYSTEMTIME st{};
        GetLocalTime(&st);
        wchar_t buf[32]{};
        swprintf_s(buf, L"%02d:%02d:%02d", st.wHour, st.wMinute, st.wSecond);
        return buf;
    }

    HFONT CreateCompactFont(HDC hdc, int targetPixelHeight)
    {
        HFONT curFont = static_cast<HFONT>(GetCurrentObject(hdc, OBJ_FONT));
        LOGFONTW lf{};
        if (curFont && GetObjectW(curFont, sizeof(lf), &lf) > 0)
        {
            lf.lfHeight = -std::max(7, targetPixelHeight);
            lf.lfWidth = 0;
            return CreateFontIndirectW(&lf);
        }
        return CreateFontW(-std::max(7, targetPixelHeight), 0, 0, 0, FW_NORMAL,
                           FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                           OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                           CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    }
}

struct IpGeoData
{
    bool valid = false;
    std::wstring ip = L"Нет сети";
    std::wstring country = L"Неизвестно";
    std::wstring countryCode;
    std::wstring region;
    std::wstring city;
    std::wstring isp;
    std::wstring org;
    std::wstring asn;
    std::wstring updatedAt;
    std::vector<uint8_t> flagPng;
    uint64_t flagGeneration = 0;
};

class CIPLocationPlugin;

class CIpDisplayItem : public IPluginItem
{
public:
    enum class Mode
    {
        FlagAndIp,
        FlagAndLocation,
        FlagCodeAndIp,
        FlagAboveCode
    };

    CIpDisplayItem(CIPLocationPlugin& owner, Mode mode)
        : m_owner(owner), m_mode(mode) {}

    const wchar_t* GetItemName() const override;
    const wchar_t* GetItemId() const override;
    const wchar_t* GetItemLableText() const override { return L""; }
    const wchar_t* GetItemValueText() const override;
    const wchar_t* GetItemValueSampleText() const override;
    bool IsCustomDraw() const override { return true; }
    int GetItemWidth() const override;
    int GetItemWidthEx(void* hDC) const override;
    void DrawItem(void* hDC, int x, int y, int w, int h, bool dark_mode) override;

private:
    std::wstring BuildDisplayText() const;

    CIPLocationPlugin& m_owner;
    Mode m_mode;
    mutable std::wstring m_cachedValue;
};

class CIPLocationPlugin : public ITMPlugin
{
public:
    static CIPLocationPlugin& Instance()
    {
        static CIPLocationPlugin inst;
        return inst;
    }

    ~CIPLocationPlugin() override
    {
        m_stopping = true;
        if (m_worker.joinable())
            m_worker.join();
    }

    IPluginItem* GetItem(int index) override
    {
        switch (index)
        {
        case 0: return &m_itemIp;
        case 1: return &m_itemLoc;
        case 2: return &m_itemCodeIp;
        case 3: return &m_itemMini;
        default: return nullptr;
        }
    }

    void DataRequired() override
    {
        ULONGLONG now = GetTickCount64();
        if (!m_fetching.load() && (m_lastFetchMs == 0 || now - m_lastFetchMs >= 30000))
        {
            if (m_worker.joinable())
                m_worker.join();
            m_fetching = true;
            m_lastFetchMs = now;
            m_worker = std::thread([this]() { FetchThread(); });
        }
    }

    const wchar_t* GetInfo(PluginInfoIndex index) override
    {
        switch (index)
        {
        case TMI_NAME:        return L"IP и Геолокация (RU)";
        case TMI_DESCRIPTION: return L"Отображает внешний IP, цветной флаг страны, город и провайдера на русском языке.";
        case TMI_AUTHOR:      return L"Custom RU Plugin";
        case TMI_COPYRIGHT:   return L"MIT";
        case TMI_VERSION:     return L"1.1.0";
        case TMI_URL:         return L"https://github.com/zhongyang219/TrafficMonitorPlugins";
        default:              return L"";
        }
    }

    OptionReturn ShowOptionsDialog(void* /*hParent*/) override
    {
        return OR_OPTION_NOT_PROVIDED;
    }

    const wchar_t* GetTooltipInfo() override
    {
        std::lock_guard<std::mutex> lock(m_dataMutex);
        if (!m_data.valid)
        {
            m_tooltip = L"IP-адрес: " + m_data.ip + L"\nОжидание ответа от сервиса геолокации...";
            return m_tooltip.c_str();
        }

        std::wstring tip;
        tip += L"IP-адрес: " + m_data.ip;
        tip += L"\nСтрана: " + m_data.country;
        if (!m_data.countryCode.empty())
            tip += L" (" + m_data.countryCode + L")";
        if (!m_data.region.empty())
            tip += L"\nРегион: " + m_data.region;
        if (!m_data.city.empty())
            tip += L"\nГород: " + m_data.city;
        if (!m_data.isp.empty())
            tip += L"\nПровайдер: " + m_data.isp;
        if (!m_data.org.empty() && m_data.org != m_data.isp)
            tip += L"\nОрганизация: " + m_data.org;
        if (!m_data.asn.empty())
            tip += L"\nAS: " + m_data.asn;
        if (!m_data.updatedAt.empty())
            tip += L"\nОбновлено: " + m_data.updatedAt;

        m_tooltip = std::move(tip);
        return m_tooltip.c_str();
    }

    void OnExtenedInfo(ExtendedInfoIndex index, const wchar_t* data) override
    {
        if (index == EI_VALUE_TEXT_COLOR && data && *data)
        {
            m_textColor = static_cast<COLORREF>(wcstoul(data, nullptr, 10));
            m_hasTextColor = true;
        }
    }

    void OnInitialize(ITrafficMonitor* pApp) override
    {
        m_pApp = pApp;
    }

    IpGeoData GetDataSnapshot() const
    {
        std::lock_guard<std::mutex> lock(m_dataMutex);
        return m_data;
    }

    bool TryGetTextColor(COLORREF& outColor) const
    {
        if (!m_hasTextColor)
            return false;
        outColor = m_textColor;
        return true;
    }

    void EnsureGdiplusAndDrawFlag(HDC hdc, int x, int y, int w, int h, const std::vector<uint8_t>& pngBytes, uint64_t generation)
    {
        if (pngBytes.empty())
            return;

        std::call_once(m_gdipOnce, [this]() {
            Gdiplus::GdiplusStartupInput input;
            if (Gdiplus::GdiplusStartup(&m_gdipToken, &input, nullptr) == Gdiplus::Ok)
                m_gdipReady = true;
        });
        if (!m_gdipReady)
            return;

        std::lock_guard<std::mutex> lock(m_uiBitmapMutex);
        if (!m_cachedFlagBmp || m_cachedGeneration != generation)
        {
            m_cachedFlagBmp.reset();
            HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, pngBytes.size());
            if (hMem)
            {
                void* pMem = GlobalLock(hMem);
                if (pMem)
                {
                    std::memcpy(pMem, pngBytes.data(), pngBytes.size());
                    GlobalUnlock(hMem);
                    IStream* pStream = nullptr;
                    if (SUCCEEDED(CreateStreamOnHGlobal(hMem, TRUE, &pStream)) && pStream)
                    {
                        std::unique_ptr<Gdiplus::Bitmap> decoded(Gdiplus::Bitmap::FromStream(pStream));
                        if (decoded && decoded->GetLastStatus() == Gdiplus::Ok && decoded->GetWidth() > 0)
                        {
                            auto copy = std::make_unique<Gdiplus::Bitmap>(
                                decoded->GetWidth(), decoded->GetHeight(), PixelFormat32bppPARGB);
                            Gdiplus::Graphics cg(copy.get());
                            cg.DrawImage(decoded.get(), 0, 0,
                                         static_cast<INT>(decoded->GetWidth()),
                                         static_cast<INT>(decoded->GetHeight()));
                            m_cachedFlagBmp = std::move(copy);
                            m_cachedGeneration = generation;
                        }
                        pStream->Release();
                    }
                    else
                    {
                        GlobalFree(hMem);
                    }
                }
                else
                {
                    GlobalFree(hMem);
                }
            }
        }

        if (m_cachedFlagBmp)
        {
            Gdiplus::Graphics g(hdc);
            g.SetInterpolationMode(Gdiplus::InterpolationModeHighQualityBicubic);
            g.DrawImage(m_cachedFlagBmp.get(), x, y, w, h);
        }
    }

private:
    CIPLocationPlugin()
        : m_itemIp(*this, CIpDisplayItem::Mode::FlagAndIp),
          m_itemLoc(*this, CIpDisplayItem::Mode::FlagAndLocation),
          m_itemCodeIp(*this, CIpDisplayItem::Mode::FlagCodeAndIp),
          m_itemMini(*this, CIpDisplayItem::Mode::FlagAboveCode)
    {
        m_data.ip = L"Загрузка...";
    }

    void FetchThread()
    {
        struct ScopeExit
        {
            std::atomic<bool>& flag;
            ~ScopeExit() { flag = false; }
        } guard{ m_fetching };

        if (m_stopping)
            return;

        IpGeoData next;
        std::vector<uint8_t> body;

        // 1. Основной источник: ip-api.com (отдаёт названия стран/регионов/городов на русском)
        if (HttpGet(L"ip-api.com", INTERNET_DEFAULT_HTTP_PORT,
                    L"/json/?lang=ru&fields=status,country,countryCode,regionName,city,isp,org,as,query",
                    false, body))
        {
            std::string json(body.begin(), body.end());
            if (ExtractJsonString(json, "status") == "success")
            {
                next.valid = true;
                next.ip = Utf8ToWide(ExtractJsonString(json, "query"));
                next.country = Utf8ToWide(ExtractJsonString(json, "country"));
                next.countryCode = Utf8ToWide(ExtractJsonString(json, "countryCode"));
                next.region = Utf8ToWide(ExtractJsonString(json, "regionName"));
                next.city = Utf8ToWide(ExtractJsonString(json, "city"));
                next.isp = Utf8ToWide(ExtractJsonString(json, "isp"));
                next.org = Utf8ToWide(ExtractJsonString(json, "org"));
                next.asn = Utf8ToWide(ExtractJsonString(json, "as"));
            }
        }

        // 2. Резервный источник: ipwho.is (HTTPS + русский язык)
        if (!next.valid && !m_stopping &&
            HttpGet(L"ipwho.is", INTERNET_DEFAULT_HTTPS_PORT, L"/?lang=ru", true, body))
        {
            std::string json(body.begin(), body.end());
            std::string ip = ExtractJsonString(json, "ip");
            if (!ip.empty())
            {
                next.valid = true;
                next.ip = Utf8ToWide(ip);
                next.country = Utf8ToWide(ExtractJsonString(json, "country"));
                next.countryCode = Utf8ToWide(ExtractJsonString(json, "country_code"));
                next.region = Utf8ToWide(ExtractJsonString(json, "region"));
                next.city = Utf8ToWide(ExtractJsonString(json, "city"));
                next.isp = Utf8ToWide(ExtractJsonString(json, "isp"));
                next.org = Utf8ToWide(ExtractJsonString(json, "org"));
            }
        }

        if (!next.valid)
        {
            std::lock_guard<std::mutex> lock(m_dataMutex);
            if (!m_data.valid)
                m_data.ip = L"Ошибка сети";
            return;
        }

        next.updatedAt = FormatCurrentTime();

        std::wstring prevCode;
        std::vector<uint8_t> prevPng;
        uint64_t prevGen = 0;
        {
            std::lock_guard<std::mutex> lock(m_dataMutex);
            prevCode = m_data.countryCode;
            prevPng = m_data.flagPng;
            prevGen = m_data.flagGeneration;
        }

        if (!next.countryCode.empty())
        {
            if (next.countryCode == prevCode && !prevPng.empty())
            {
                next.flagPng = std::move(prevPng);
                next.flagGeneration = prevGen;
            }
            else if (!m_stopping)
            {
                std::wstring lowerCode = next.countryCode;
                for (auto& ch : lowerCode)
                    ch = static_cast<wchar_t>(towlower(ch));
                std::wstring flagPath = L"/w40/" + lowerCode + L".png";
                std::vector<uint8_t> png;
                if (HttpGet(L"flagcdn.com", INTERNET_DEFAULT_HTTPS_PORT, flagPath.c_str(), true, png))
                {
                    next.flagPng = std::move(png);
                    next.flagGeneration = prevGen + 1;
                }
            }
        }

        {
            std::lock_guard<std::mutex> lock(m_dataMutex);
            m_data = std::move(next);
        }
    }

    CIpDisplayItem m_itemIp;
    CIpDisplayItem m_itemLoc;
    CIpDisplayItem m_itemCodeIp;
    CIpDisplayItem m_itemMini;

    mutable std::mutex m_dataMutex;
    IpGeoData m_data;
    std::wstring m_tooltip;

    std::atomic<bool> m_fetching{ false };
    std::atomic<bool> m_stopping{ false };
    ULONGLONG m_lastFetchMs = 0;
    std::thread m_worker;

    ITrafficMonitor* m_pApp = nullptr;
    COLORREF m_textColor = RGB(255, 255, 255);
    bool m_hasTextColor = false;

    std::once_flag m_gdipOnce;
    ULONG_PTR m_gdipToken = 0;
    bool m_gdipReady = false;
    std::mutex m_uiBitmapMutex;
    std::unique_ptr<Gdiplus::Bitmap> m_cachedFlagBmp;
    uint64_t m_cachedGeneration = 0;
};

const wchar_t* CIpDisplayItem::GetItemName() const
{
    switch (m_mode)
    {
    case Mode::FlagAndIp:       return L"Флаг + IP-адрес";
    case Mode::FlagAndLocation: return L"Флаг + Страна/Город";
    case Mode::FlagCodeAndIp:   return L"Флаг + Код + IP";
    case Mode::FlagAboveCode:   return L"Флаг + Код снизу (мини)";
    default:                    return L"IP";
    }
}

const wchar_t* CIpDisplayItem::GetItemId() const
{
    switch (m_mode)
    {
    case Mode::FlagAndIp:       return L"ip_loc_ru_flag_ip";
    case Mode::FlagAndLocation: return L"ip_loc_ru_flag_loc";
    case Mode::FlagCodeAndIp:   return L"ip_loc_ru_flag_code_ip";
    case Mode::FlagAboveCode:   return L"ip_loc_ru_flag_code_mini";
    default:                    return L"ip_loc_ru_default";
    }
}

std::wstring CIpDisplayItem::BuildDisplayText() const
{
    IpGeoData d = m_owner.GetDataSnapshot();
    switch (m_mode)
    {
    case Mode::FlagAndIp:
        return d.ip;
    case Mode::FlagAndLocation:
        if (!d.valid)
            return d.ip;
        if (!d.city.empty() && !d.country.empty())
            return d.country + L", " + d.city;
        return !d.country.empty() ? d.country : d.ip;
    case Mode::FlagCodeAndIp:
        if (!d.valid || d.countryCode.empty())
            return d.ip;
        return d.countryCode + L" • " + d.ip;
    case Mode::FlagAboveCode:
        if (!d.valid)
            return (d.ip == L"Ошибка сети") ? L"--" : L"...";
        return !d.countryCode.empty() ? d.countryCode : L"--";
    default:
        return d.ip;
    }
}

const wchar_t* CIpDisplayItem::GetItemValueText() const
{
    m_cachedValue = BuildDisplayText();
    return m_cachedValue.c_str();
}

const wchar_t* CIpDisplayItem::GetItemValueSampleText() const
{
    switch (m_mode)
    {
    case Mode::FlagAndIp:       return L"255.255.255.255";
    case Mode::FlagAndLocation: return L"Нидерланды, Амстердам";
    case Mode::FlagCodeAndIp:   return L"NL • 255.255.255.255";
    case Mode::FlagAboveCode:   return L"DE";
    default:                    return L"255.255.255.255";
    }
}

int CIpDisplayItem::GetItemWidth() const
{
    return (m_mode == Mode::FlagAboveCode) ? 32 : 140;
}

int CIpDisplayItem::GetItemWidthEx(void* hDC) const
{
    HDC hdc = static_cast<HDC>(hDC);
    if (!hdc)
        return GetItemWidth();

    IpGeoData d = m_owner.GetDataSnapshot();
    std::wstring text = BuildDisplayText();

    int dpiY = GetDeviceCaps(hdc, LOGPIXELSY);
    if (dpiY <= 0) dpiY = 96;

    if (m_mode == Mode::FlagAboveCode)
    {
        int flagH = MulDiv(12, dpiY, 96);
        int flagW = (flagH * 3) / 2;

        HFONT compactFont = CreateCompactFont(hdc, MulDiv(10, dpiY, 96));
        HFONT oldFont = compactFont ? static_cast<HFONT>(SelectObject(hdc, compactFont)) : nullptr;

        RECT rc{ 0, 0, 0, 0 };
        DrawTextW(hdc, text.c_str(), -1, &rc, DT_CALCRECT | DT_SINGLELINE | DT_NOPREFIX);
        int textW = rc.right - rc.left;

        if (compactFont)
        {
            SelectObject(hdc, oldFont);
            DeleteObject(compactFont);
        }

        return std::max(flagW, textW) + MulDiv(6, dpiY, 96);
    }

    RECT rc{ 0, 0, 0, 0 };
    DrawTextW(hdc, text.c_str(), -1, &rc, DT_CALCRECT | DT_SINGLELINE | DT_NOPREFIX);
    int textW = rc.right - rc.left;

    int flagH = MulDiv(12, dpiY, 96);
    int flagW = (flagH * 3) / 2;
    int gap = MulDiv(4, dpiY, 96);

    int extra = d.flagPng.empty() ? 0 : (flagW + gap);
    return extra + textW + MulDiv(4, dpiY, 96);
}

void CIpDisplayItem::DrawItem(void* hDC, int x, int y, int w, int h, bool dark_mode)
{
    HDC hdc = static_cast<HDC>(hDC);
    if (!hdc)
        return;

    IpGeoData d = m_owner.GetDataSnapshot();
    std::wstring text = BuildDisplayText();

    int dpiY = GetDeviceCaps(hdc, LOGPIXELSY);
    if (dpiY <= 0) dpiY = 96;

    int oldBk = SetBkMode(hdc, TRANSPARENT);
    COLORREF targetColor = dark_mode ? RGB(255, 255, 255) : RGB(0, 0, 0);
    m_owner.TryGetTextColor(targetColor);
    COLORREF oldColor = SetTextColor(hdc, targetColor);

    if (m_mode == Mode::FlagAboveCode)
    {
        bool hasFlag = !d.flagPng.empty();
        int fontPx = std::min(std::max(8, h * 34 / 100), MulDiv(10, dpiY, 96));
        HFONT compactFont = CreateCompactFont(hdc, fontPx);
        HFONT oldFont = compactFont ? static_cast<HFONT>(SelectObject(hdc, compactFont)) : nullptr;

        TEXTMETRICW tm{};
        GetTextMetricsW(hdc, &tm);
        int capH = std::max(6, static_cast<int>(tm.tmAscent - tm.tmInternalLeading));

        int gap = (h >= MulDiv(26, dpiY, 96)) ? MulDiv(2, dpiY, 96) : 1;
        int flagH = std::min(std::max(7, h * 40 / 100), MulDiv(12, dpiY, 96));
        if (hasFlag && (flagH + gap + capH > h - 2))
            flagH = std::max(7, h - 2 - gap - capH);
        int flagW = std::min(w - 2, (flagH * 3) / 2);
        flagH = std::max(6, (flagW * 2) / 3);

        int totalH = hasFlag ? (flagH + gap + capH) : capH;
        int startY = y + std::max(0, (h - totalH) / 2);

        if (hasFlag)
        {
            int flagX = x + (w - flagW) / 2;
            m_owner.EnsureGdiplusAndDrawFlag(hdc, flagX, startY, flagW, flagH, d.flagPng, d.flagGeneration);
            startY += flagH + gap;
        }

        int textTop = startY - static_cast<int>(tm.tmInternalLeading);
        RECT textRc{ x, textTop, x + w, std::max(y + h, textTop + static_cast<int>(tm.tmHeight)) };
        DrawTextW(hdc, text.c_str(), -1, &textRc, DT_TOP | DT_CENTER | DT_SINGLELINE | DT_NOPREFIX);

        if (compactFont)
        {
            SelectObject(hdc, oldFont);
            DeleteObject(compactFont);
        }
    }
    else
    {
        int flagH = std::min(std::max(8, h - 4), MulDiv(12, dpiY, 96));
        int flagW = (flagH * 3) / 2;
        int gap = MulDiv(4, dpiY, 96);
        int curX = x + 1;

        if (!d.flagPng.empty())
        {
            int flagY = y + (h - flagH) / 2;
            m_owner.EnsureGdiplusAndDrawFlag(hdc, curX, flagY, flagW, flagH, d.flagPng, d.flagGeneration);
            curX += flagW + gap;
        }

        RECT textRc{ curX, y, x + w, y + h };
        DrawTextW(hdc, text.c_str(), -1, &textRc, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
    }

    SetTextColor(hdc, oldColor);
    SetBkMode(hdc, oldBk);
}

extern "C" __declspec(dllexport) ITMPlugin* TMPluginGetInstance()
{
    return &CIPLocationPlugin::Instance();
}