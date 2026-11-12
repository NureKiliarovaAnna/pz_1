# ПЗ № 1. Власний блокчейн з нуля

## Встановлення

У PowerShell відкриваю папку проєкту. Потрібен Python 3.12 або новіший.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Запуск

```powershell
.\.venv\Scripts\python.exe run_network.py
```

Запускаються три вузли на портах `8001`, `8002` і `8003`. Зупиняю їх через `Ctrl+C`.

## Перевірки

Перед `demo.py fork` зупиняю запущену мережу, щоб звільнити порти.

```powershell
.\.venv\Scripts\python.exe -m unittest -v
.\.venv\Scripts\python.exe demo.py attacks
.\.venv\Scripts\python.exe demo.py fork
.\.venv\Scripts\python.exe experiment.py
```

Графік часу майнінгу зберігається в `results/mining_time.png`, вимірювання й статистика — у CSV-файлах у тій самій папці.

## Приклад переказу

Запускаю мережу й відкриваю другий термінал. Якщо гаманці вже створені, пропускаю команди `create`.

```powershell
$py = '.\.venv\Scripts\python.exe'
& $py wallet.py create alice
& $py wallet.py create bob

$alice = (& $py wallet.py show alice | ConvertFrom-Json).address
$bob = (& $py wallet.py show bob | ConvertFrom-Json).address
$node = 'http://127.0.0.1:8001'
$miner = @{ miner = $alice } | ConvertTo-Json

Invoke-RestMethod "$node/mine" -Method Post -ContentType 'application/json' -Body $miner
& $py wallet.py send alice $bob 10 --fee 2
Invoke-RestMethod "$node/mine" -Method Post -ContentType 'application/json' -Body $miner
Invoke-RestMethod "$node/balance/$bob"
```

Першим блоком поповнюю баланс Аліси. Після переказу майню ще один блок і перевіряю баланс Боба.