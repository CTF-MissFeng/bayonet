chmod +x tools/scan/Chromium/crawlergo
chmod +x tools/scan/xray/xray
nohup python -u app.py > logs/web.log 2>&1 &
nohup python -u run_chromium.py > logs/chromium.log 2>&1 &
nohup python -u run_subdomain.py > logs/subdomain.log 2>&1 &
nohup python -u run_portscan.py > logs/portscan.log 2>&1 &
nohup python -u run_urlscan.py > logs/urlscan.log 2>&1 &
nohup python -u run_xray.py > logs/xray.log 2>&1 &