# Straja Gateway Auto-Start on macOS (LaunchDaemon)

Goal: run Straja as a launch daemon so it starts automatically on boot.

Assumptions:

- Straja listens on `127.0.0.1:8080` by default.
- Your Straja files live in `/Users/USERNAME/straja`.

## Step 1 -- Ensure stable folder structure

Your directory should look like:

```text
/Users/USERNAME/straja/straja
/Users/USERNAME/straja/run.sh
/Users/USERNAME/straja/straja.yaml
/Users/USERNAME/straja/lib/
```

Notes:

- `straja.yaml` is optional.
- `lib/` is optional.

## Step 2 -- Verify it runs manually

Run:

```bash
/bin/bash /Users/USERNAME/straja/run.sh --help
```

Then start it:

```bash
/bin/bash /Users/USERNAME/straja/run.sh
```

Confirm:

```bash
curl -sS -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/console/
```

Stop it (`Ctrl+C`) before continuing.

## Step 3 -- Create LaunchDaemon file

Create:

`/Library/LaunchDaemons/ai.straja.gateway.plist`

Contents:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>ai.straja.gateway</string>

  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>/Users/USERNAME/straja/run.sh</string>
  </array>

  <key>WorkingDirectory</key>
  <string>/Users/USERNAME/straja</string>

  <key>RunAtLoad</key>
  <true/>

  <key>KeepAlive</key>
  <true/>

  <key>StandardOutPath</key>
  <string>/Library/Logs/ai.straja.gateway.out.log</string>

  <key>StandardErrorPath</key>
  <string>/Library/Logs/ai.straja.gateway.err.log</string>
</dict>
</plist>
```

## Step 4 -- Fix permissions

```bash
sudo chown root:wheel /Library/LaunchDaemons/ai.straja.gateway.plist
sudo chmod 644 /Library/LaunchDaemons/ai.straja.gateway.plist
sudo plutil -lint /Library/LaunchDaemons/ai.straja.gateway.plist
```

## Step 5 -- Add required environment variables (if needed)

Create `EnvironmentVariables` dictionary:

```bash
sudo /usr/libexec/PlistBuddy -c 'Add :EnvironmentVariables dict' /Library/LaunchDaemons/ai.straja.gateway.plist 2>/dev/null || true
```

Add required keys:

```bash
sudo /usr/libexec/PlistBuddy -c 'Add :EnvironmentVariables:STRAJA_CONSOLE_SESSION_SECRET string YOUR_SECRET' /Library/LaunchDaemons/ai.straja.gateway.plist
sudo /usr/libexec/PlistBuddy -c 'Add :EnvironmentVariables:STRAJA_TRUST_KEY string YOUR_TRUST_KEY' /Library/LaunchDaemons/ai.straja.gateway.plist
sudo /usr/libexec/PlistBuddy -c 'Add :EnvironmentVariables:OPENAI_API_KEY string YOUR_OPENAI_KEY' /Library/LaunchDaemons/ai.straja.gateway.plist
```

If a key already exists, use `Set` instead of `Add`.

Verify:

```bash
sudo /usr/libexec/PlistBuddy -c 'Print :EnvironmentVariables' /Library/LaunchDaemons/ai.straja.gateway.plist
```

## Step 6 -- Load the daemon

```bash
sudo launchctl unload /Library/LaunchDaemons/ai.straja.gateway.plist 2>/dev/null
sudo launchctl load -w /Library/LaunchDaemons/ai.straja.gateway.plist
```

Check:

```bash
sudo launchctl list | grep ai.straja.gateway || true
```

## Step 7 -- Verify locally

```bash
curl -sS -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/console/
```

Should return `200`.

## Step 8 -- Verify after reboot

Restart your Mac.

After boot:

```bash
curl -sS -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/console/
```

If it fails:

```bash
sudo tail -n 80 /Library/Logs/ai.straja.gateway.err.log
```

## Step 9 -- Updating Straja later

Replace the binary at:

`/Users/USERNAME/straja/straja`

Then restart daemon:

```bash
sudo launchctl kickstart -k system/ai.straja.gateway
```

## Step 10 -- Remove daemon (if needed)

```bash
sudo launchctl bootout system /Library/LaunchDaemons/ai.straja.gateway.plist
sudo rm -f /Library/LaunchDaemons/ai.straja.gateway.plist
```
