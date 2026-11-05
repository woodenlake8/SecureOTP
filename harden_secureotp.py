#!/usr/bin/env python3
"""Apply privacy hardening to a local checkout of 26JATIN/SecureOTP.
Run: python3 harden_secureotp.py /path/to/SecureOTP
"""
from pathlib import Path
import re, sys

root = Path(sys.argv[1] if len(sys.argv) > 1 else '.').resolve()
base = root / 'app/src/main/java/com/otpextractor/gmail'
listener = base / 'service/OtpListener.kt'
extractor = base / 'utils/OtpExtractor.kt'
manifest = root / 'app/src/main/AndroidManifest.xml'
for p in (listener, extractor, manifest):
    if not p.is_file():
        raise SystemExit(f'Missing expected file: {p}')

l = listener.read_text()
e = extractor.read_text()
m = manifest.read_text()

# Remove all Android logging calls from sensitive processing paths.
# Current upstream logging statements are single-line; refuse unexpected multiline calls.
for p, content in ((listener,l),(extractor,e)):
    if re.search(r'\bLog\.[a-zA-Z]+\s*\(\s*$', content, re.M):
        raise SystemExit(f'Unexpected multiline logging in {p}; review manually')
    if re.search(r'\bLog\.', content) and not re.search(r'^\s*Log\.[a-zA-Z]+\([^\n]*\)\s*$', content, re.M):
        raise SystemExit(f'Unexpected logging format in {p}; review manually')
    content = re.sub(r'^\s*Log\.[a-zA-Z]+\([^\n]*\)\s*\n', '', content, flags=re.M)
    content = re.sub(r'^import android\.util\.Log\n', '', content, flags=re.M)
    if p == listener: l = content
    else: e = content

# Prevent creation of a second notification containing the OTP.
old = '''                            val appName = getAppName(sbn.packageName)
                            showOtpNotification(otp, appName)'''
if old not in l:
    raise SystemExit('Listener notification call changed upstream; review manually')
l = l.replace(old, '', 1)
# Remove notification display method, retaining other code.
start = l.find('    private fun showOtpNotification(otp: String, appName: String) {')
end = l.find('    override fun onListenerConnected()', start)
if start < 0 or end < 0:
    raise SystemExit('Listener notification function changed upstream; review manually')
l = l[:start] + l[end:]

# Mark OTP as sensitive so supporting Android keyboards can conceal previews.
old = '            clipboard.setPrimaryClip(clip)'
new = '''            // Android 13+ clipboard preview and supporting keyboards conceal sensitive clips.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                clip.description.extras = android.os.PersistableBundle().apply {
                    putBoolean("android.content.extra.IS_SENSITIVE", true)
                }
            }
            clipboard.setPrimaryClip(clip)'''
if old not in l:
    raise SystemExit('Clipboard implementation changed upstream; review manually')
l = l.replace(old, new, 1)

# Prevent app-private preferences from being included in Android backup.
if 'android:allowBackup="true"' not in m:
    raise SystemExit('Backup setting changed upstream; review manually')
m = m.replace('android:allowBackup="true"', 'android:allowBackup="false"', 1)

# Fail closed if sensitive logging remains.
for p, content in ((listener,l),(extractor,e)):
    if re.search(r'\bLog\.', content):
        raise SystemExit(f'Logging remains in {p}')

listener.write_text(l)
extractor.write_text(e)
manifest.write_text(m)
print('Patched OtpListener.kt, OtpExtractor.kt and AndroidManifest.xml')
print('Review git diff, build, and test Gmail/Proton Mail before installation.')