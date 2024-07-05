
local http = require "http"

function check_cve_2023_22515(tgt)
  local response = http.get(tgt, {
    headers = {
      ["User-Agent"] = "Confluence",
    },
  })

  if response.code == 200 then
    local version = response.headers["X-Confluence-Version"]
    if version then
      local major, minor = string.match(version, "%d+%.%d+")
      if major == "8" and tonumber(minor) <= 5 then
        return {
          result = true,
          version = version,
          output = "CVE-2023-22515: Уязвимость обнаружена на " .. tgt .. " (версия: " .. version .. ")."
        }
      else
        return {
          result = false,
          version = version,
          output = "CVE-2023-22515: Уязвимость не обнаружена на " .. tgt .. " (версия: " .. version .. ")."
        }
      end
    else
      return {
        result = false,
        output = "CVE-2023-22515: Не удалось получить версию Confluence с " .. tgt .. "."
      }
    end
  else
    return {
      result = false,
      output = "Ошибка при проверке " .. tgt .. ": HTTP код " .. response.code .. "."
    }
  end
end

-- Запускаем скрипт
function main(host, port)
  local tgt = string.format("http://%s:%d", host, port)
  return check_cve_2023_22515(tgt)
end

-- NSE script registration
local script = {
  name = "cve-2023-22515",
  author = "Your Name",
  description = "Checks for CVE-2023-22515 (Confluence OGNL Injection)",
  categories = { "exploit", "vuln", "default" },
  license = "GPLv2",
  targets = {
    {
      name = "Confluence",
      port = 8090,
      protocol = "tcp",
      version = "8.0.0 - 8.5.1",
      description = "Confluence versions 8.0.0 - 8.5.1 are vulnerable to CVE-2023-22515.",
    },
  },
  main = main,
}

-- Register the script
nmap.register_script(script)

    main()
