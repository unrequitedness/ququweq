pmAPI-1.0.7-release (~100%)

[WARNING] Если Вы в очередной раз не видите тут ORM - соболезную

** Скачивание: **

- git clone https://github.com/unrequitedness/ququweq.git
- cd ququweq

** Запуск: **
- dotnet run

** Тестирование (малая часть): **

# Создание бд:
Invoke-RestMethod -Uri "http://localhost:5000/initdb" -Method POST

# Создание тест юзера:
Invoke-RestMethod -Uri "http://localhost:5000/create-test-user" -Method POST

# Получение токена:
$authResponse = Invoke-RestMethod -Uri "http://localhost:5000/api/v1/SignIn" -Method POST -ContentType "application/json" -Body '{"Name":"test","Pwd":"123"}'
$token = $authResponse.Token
Write-Host "$token"

Все остальное сами проверите (при желании).
