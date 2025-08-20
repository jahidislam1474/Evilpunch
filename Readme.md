<p align="center">
  <img src="evilpunch/public/static/images/evilpunch.png" alt="EvilPunch Logo" width="180" />
</p>

### EvilPunch — Offensive Reverse Proxy

<p align="center">
  <a href="https://www.djangoproject.com/" target="_blank"><img alt="Built with Django" src="https://img.shields.io/badge/built%20with-Django-0C4B33?logo=django&logoColor=white"></a>
  <a href="https://python.org" target="_blank"><img alt="Python" src="https://img.shields.io/badge/python-3.x-3776AB?logo=python&logoColor=white"></a>
  <a href="https://youtu.be/N5iu_X73hy0" target="_blank"><img alt="Demo" src="https://img.shields.io/badge/watch-demo-FF0000?logo=youtube&logoColor=white"></a>
  <img alt="Status" src="https://img.shields.io/badge/status-active-success">
  
</p>

<p align="center"><i>Fast, configurable reverse proxy dashboard for authorized red teaming and security research.</i></p>

## Table of Contents

- [Demo](#demo)
- [Features](#features)
- [Run the Dashboard](#run-the-dashboard)
- [Community & Resources](#community--resources)
- [Legal & Ethical Notice](#legal--ethical-notice)
- [License & Permissions](#license--permissions)

## Demo

- **Watch the demo**: [YouTube — EvilPunch Demo](https://youtu.be/N5iu_X73hy0)

<a href="https://youtu.be/N5iu_X73hy0" target="_blank">
  <img src="https://img.youtube.com/vi/N5iu_X73hy0/hqdefault.jpg" alt="EvilPunch Demo Video" width="640" />
  
 </a>

## Features

- **Web dashboard**: Admin login ensured from `config.json`.
- **Config-driven**: Set host, port, and credentials in `evilpunch/config/config.json`.
- **One-liner start**: `./run.sh` handles env, deps, migrate, and run.
- **Django 5**: Modern framework, SQLite by default, easy to extend.
- **Static assets**: Bundled images and styles via `public/static`.
## Run the Dashboard

### Quick start (one command)

```bash
chmod +x run.sh && ./run.sh -d # for devloper mode

chmod +x run.sh && ./run.sh -p # for production mode
```

This will:

- Install Python (if missing) and tools for your OS
- Create/activate a virtual environment
- Install dependencies from `requirements.txt`
- Run database migrations
- Start the Django server using the configured host/port

### Manual setup

```bash
# 1) Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# 2) Install dependencies
pip install -r requirements.txt

# 3) Run migrations and start the server
cd evilpunch
python manage.py migrate
python manage.py runserver
```

### Configure host, port, and admin login

- Edit `evilpunch/config/config.json`:
  - `dashboard_host` (default `0.0.0.0`) and `dashboard_port` (default `9000`)
  - `dashboard_username` and `dashboard_password`
- On startup, these credentials are ensured for an admin user.
- To use a different config path, set `REVERSE_PROXY_CONFIG_PATH` or `CONFIG_PATH`.

### Access the dashboard

- Local: `http://localhost:9000`
- Remote/LAN: `http://<server-ip-or-hostname>:9000` (open the port in your firewall)
- Log in with the credentials from `config.json` (default `admin` / `admin`). Change them immediately.

### Notes

- The development server binds to the host/port from `evilpunch/config/config.json`.
- If exposing beyond localhost, set `ALLOWED_HOSTS` in `evilpunch/evilpunch/settings.py` for production use.



## Community & Resources

Everything you need to get the most from EvilPunch — tutorials, docs, tools, courses, and community — all in one place.

- **YouTube Channel**: Step-by-step tutorials, feature deep dives, and updates — [Open YouTube](https://www.youtube.com/@FluxxSet)
- **Official Website**: Latest news, documentation, and announcements — [Open Website](https://fluxxset.com/)
- **Community Forum**: Ask questions, share knowledge, explore solutions — [Open Forum](https://fluxxset.com/)
- **Shop & Training Courses**: Level up with structured learning and premium content — [Open Shop](https://fourthwall.fluxxset.com/)
- **Tools**: Companion tools and utilities to boost your workflow — [Open Tools](https://tools.fluxxset.com/)
- **Telegram Community**: Fast updates, announcements, and community support — [Open Telegram](https://t.me/fluxxset)

Quick links:

- **Visit Forum**: [fluxxset.com](https://fluxxset.com/)
- **Join Telegram**: [t.me/fluxxset](https://t.me/fluxxset)

## Legal & Ethical Notice

This project, including all associated modules, scripts, and user interfaces, is provided strictly for legitimate security testing and educational purposes by authorized professionals. Unauthorized use may be illegal and could lead to criminal and civil penalties.

**Phishing is illegal without explicit permission.** You must have written authorization (e.g., contract, letter of engagement, or signed scope) from the system owner before performing any testing.

### Intended Audience

- Red teamers and penetration testers working under a valid Statement of Work.
- Blue teamers and defenders conducting adversary emulation in controlled environments.
- Security researchers and educators in lab settings with consent.

### You Agree To

- Use this tool only with explicit, written authorization from asset owners.
- Comply with all applicable laws and regulations in your jurisdiction.
- Protect captured data and handle it according to your engagement’s confidentiality rules.
- Avoid targeting uninvolved third parties or production environments without scope approval.

### Data Handling

- Minimize data collection to what is necessary for the engagement.
- Store sensitive data securely and encrypt it at rest and in transit when possible.
- Purge data promptly at the end of an engagement or per contractual obligations.

### Disclaimer

The authors and contributors are not responsible for any misuse or damage caused by this software. Using this project implies that you understand and accept these terms and will use it responsibly and lawfully.

## License & Permissions

You indicated you want a license that allows free use but requires permission for modifications and for organizational/commercial use. The following placeholder reflects that intent. Feel free to replace or refine this section with your final license text.

- **Free Use**: You may download, install, and use this project for personal, educational, and internal research purposes at no charge.
- **Permission Required**: You must obtain prior written permission from the project owner before any of the following:
  - Modifying the source code and distributing modified versions.
  - Using the software in organizational, client, or commercial engagements.
  - Redistributing binaries, packages, or derivative works.
  - Offering paid services, hosting, or support based on this project.
- **Attribution**: Do not remove or alter notices, credits, or branding.
- **How to Request Permission**: Contact the maintainers via Telegram at [t.me/fluxxset](https://t.me/fluxxset) or via the website [fluxxset.com](https://fluxxset.com/).
- **No Warranty**: The software is provided “as is” without warranty of any kind.

If you prefer a standard license, consider using a source-available license (e.g., BUSL-1.1 or a custom source-available grant) tailored to your requirements


