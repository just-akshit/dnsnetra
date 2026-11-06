# DNSNetra production deployment (Ubuntu 24.04)

## 1. Host and DNS
- Static IP, `dnsnetra.corp.local` resolving to it (internal DNS or `/etc/hosts` on clients).
- UEFI Secure Boot, BIOS password, LUKS on the data disk, UPS.

## 2. Database migration and SUPER_ADMIN bootstrap (run once)

1. Back up the auth tables (never skip this):

       pg_dump -Fc --table=dashboard_users --table=sessions --table=audit_logs \
         --table=password_reset_tokens dns_threat_detection > /secure/path/auth-$(date +%F).dump

2. Stop the API.
3. Apply migrations (adds the `SUPER_ADMIN` role constraint):

       /opt/dnsnetra/.venv/bin/python database/migrate.py

4. Create the first SUPER_ADMIN. There is intentionally no automatic promotion
   of the existing `admin` account, and no API path creates the first one:

       /opt/dnsnetra/.venv/bin/python scripts/create_super_admin.py --username superadmin --execute

   Move the printed one-time password into the password manager; the account
   must change it at first login.

5. Start the API, log in as the new SUPER_ADMIN, and confirm `/users` is visible.

Until step 4 runs, no account can manage an existing ADMIN. `scripts/rotate_admin_password.py`
remains the break-glass path and now accepts ADMIN or SUPER_ADMIN.

## 3. Service account and code
    sudo apt update && sudo apt install -y nginx postgresql python3.13 python3.13-venv nodejs
    sudo useradd --system --home /opt/dnsnetra --shell /usr/sbin/nologin dnsnetra
    sudo mkdir -p /opt/dnsnetra /etc/dnsnetra
    sudo cp -a . /opt/dnsnetra
    sudo chown -R dnsnetra:dnsnetra /opt/dnsnetra
    sudo -u dnsnetra python3.13 -m venv /opt/dnsnetra/.venv
    sudo -u dnsnetra /opt/dnsnetra/.venv/bin/pip install -r /opt/dnsnetra/requirements.txt

## 4. Frontend build (NEXT_PUBLIC_* is baked in at build time)
    cd /opt/dnsnetra/frontend
    sudo -u dnsnetra env NEXT_PUBLIC_API_URL=https://dnsnetra.corp.local pnpm install --frozen-lockfile
    sudo -u dnsnetra env NEXT_PUBLIC_API_URL=https://dnsnetra.corp.local pnpm build

## 5. Secrets
    sudo install -m 600 -o root -g dnsnetra deploy/api.env.example /etc/dnsnetra/api.env
    sudo sed -i "s|^AUTH_SESSION_SECRET=.*|AUTH_SESSION_SECRET=$(openssl rand -hex 32)|" /etc/dnsnetra/api.env
    sudo sed -i "s|^AUTH_CAPTCHA_SECRET=.*|AUTH_CAPTCHA_SECRET=$(openssl rand -hex 32)|" /etc/dnsnetra/api.env
    sudo editor /etc/dnsnetra/api.env   # set the database password only

## 6. TLS
    sudo ./deploy/gen-internal-cert.sh dnsnetra.corp.local

## 7. nginx
    sudo cp deploy/nginx/dnsnetra-proxy.conf /etc/nginx/snippets/dnsnetra-proxy.conf
    sudo cp deploy/nginx/dnsnetra.conf /etc/nginx/sites-available/dnsnetra.conf
    sudo ln -sf /etc/nginx/sites-available/dnsnetra.conf /etc/nginx/sites-enabled/dnsnetra.conf
    sudo rm -f /etc/nginx/sites-enabled/default
    sudo nginx -t
    sudo systemctl reload nginx

## 8. systemd
    sudo cp deploy/systemd/dnsnetra-api.service deploy/systemd/dnsnetra-web.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable --now dnsnetra-api dnsnetra-web

## 9. Firewall
    sudo ADMIN_CIDR=10.0.0.0/8 USER_CIDR=10.0.0.0/8 ./deploy/ufw-dnsnetra.sh

## 10. Verification
    ss -ltnp | grep -E ':3000|:8000'     # must show 127.0.0.1 only
    curl -k https://dnsnetra.corp.local/api/v1/auth/captcha
    curl -k -I https://dnsnetra.corp.local/login
    sudo systemctl status dnsnetra-api dnsnetra-web nginx
    sudo journalctl -u dnsnetra-api -n 50 --no-pager
