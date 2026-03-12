#!/usr/bin/env python3
"""
Build script: Encrypts the page content with AES-256-GCM.
The password is used as encryption key via PBKDF2.
The resulting index.html contains only the password screen + encrypted blob.
The password cannot be extracted from the source code.
"""

import os
import json
import base64
import hashlib
import secrets
from pathlib import Path

# Use PyCryptodome if available, otherwise fall back to cryptography
try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    USE_PYCRYPTODOME = True
except ImportError:
    USE_PYCRYPTODOME = False

PASSWORD = "Iranazadi"
INPUT_FILE = Path(__file__).parent / "dev.html"
OUTPUT_FILE = Path(__file__).parent / "index.html"


def encrypt_aes_gcm(plaintext: bytes, password: str) -> dict:
    """Encrypt using AES-256-GCM with PBKDF2 key derivation."""
    salt = secrets.token_bytes(16)
    iv = secrets.token_bytes(12)

    if USE_PYCRYPTODOME:
        key = PBKDF2(password.encode(), salt, dkLen=32, count=100000, hmac_hash_module=hashlib)
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    else:
        # Pure Python PBKDF2 + AES is complex, use subprocess to call openssl
        # Instead, we'll use a simpler approach: encode the encryption params
        # and let the browser's Web Crypto API handle it
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

        # We'll use a simple XOR stream cipher derived from the key as fallback
        # But better: just output the params and let JS do the encryption
        # Actually, let's use the built-in hmac approach
        raise ImportError("Need pycryptodome or cryptography library")

    return {
        'salt': base64.b64encode(salt).decode(),
        'iv': base64.b64encode(iv).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'tag': base64.b64encode(tag).decode(),
    }


def encrypt_webcrypto_compatible(plaintext: bytes, password: str) -> dict:
    """
    Encrypt in a way compatible with Web Crypto API decryption.
    Uses PBKDF2 for key derivation and AES-GCM for encryption.
    This works without any external Python libraries.
    """
    salt = secrets.token_bytes(16)
    iv = secrets.token_bytes(12)

    # Derive key using PBKDF2-HMAC-SHA256
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=32)

    # Since Python stdlib doesn't have AES-GCM, we'll use a different approach:
    # Encode everything and use the browser to do the actual encryption verification.
    # We'll use a simple but secure approach: encrypt with a key derived from password.

    # Try to use cryptography library
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(key)
        ciphertext_with_tag = aesgcm.encrypt(iv, plaintext, None)
        # AES-GCM appends the 16-byte tag to the ciphertext
        ciphertext = ciphertext_with_tag[:-16]
        tag = ciphertext_with_tag[-16:]
    except ImportError:
        try:
            from Crypto.Cipher import AES as AES_Crypto
            cipher = AES_Crypto.new(key, AES_Crypto.MODE_GCM, nonce=iv)
            ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        except ImportError:
            # Last resort: use openssl via subprocess
            import subprocess
            import tempfile

            with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
                f.write(plaintext)
                plaintext_file = f.name

            key_hex = key.hex()
            iv_hex = iv.hex()

            result = subprocess.run(
                ['openssl', 'enc', '-aes-256-gcm', '-nosalt',
                 '-K', key_hex, '-iv', iv_hex,
                 '-in', plaintext_file],
                capture_output=True
            )
            os.unlink(plaintext_file)

            if result.returncode != 0:
                raise RuntimeError(
                    "No AES-GCM library available. Install with: pip3 install cryptography\n"
                    f"OpenSSL error: {result.stderr.decode()}"
                )

            output = result.stdout
            ciphertext = output[:-16]
            tag = output[-16:]

    return {
        'salt': base64.b64encode(salt).decode(),
        'iv': base64.b64encode(iv).decode(),
        'data': base64.b64encode(iv + ciphertext + tag).decode(),  # Combined format for Web Crypto
    }


def build_encrypted_page(encrypted_data: dict, original_html: str) -> str:
    """Build the final HTML page with lock screen from dev.html + encrypted content."""
    import re

    # Get the style content
    style_match = re.search(r'<style>(.*?)</style>', original_html, re.DOTALL)
    styles = style_match.group(1) if style_match else ''

    # Get tailwind config
    tw_config_match = re.search(r'(<script>\s*tailwind\.config.*?</script>)', original_html, re.DOTALL)
    tw_config = tw_config_match.group(1) if tw_config_match else ''

    # Extract the lock screen HTML from dev.html (everything inside <div id="lock-screen">...</div>)
    lock_start = original_html.find('<div id="lock-screen"')
    # Find the closing </div> that matches the lock-screen div
    # The lock-screen ends right before <!-- MAIN CONTENT -->
    lock_end_marker = original_html.find('<!-- ============================================ -->\n    <!-- MAIN CONTENT')
    if lock_end_marker == -1:
        lock_end_marker = original_html.find('<div id="main-content"')
    lock_screen_html = original_html[lock_start:lock_end_marker].strip()

    # Extract the step navigation scripts (between lock screen and main content)
    # These are the scripts with goToStep, redirectAway, password toggle
    first_script_block = original_html.find('<!-- JAVASCRIPT -->')
    if first_script_block == -1:
        first_script_block = original_html.find('function goToStep')
    # Find the script block that contains goToStep
    step_scripts_match = re.search(
        r'(<script>\s*// ---- Step Navigation.*?</script>)',
        original_html, re.DOTALL
    )
    step_scripts = step_scripts_match.group(1) if step_scripts_match else ''

    # Extract context-menu/security script
    security_match = re.search(
        r"(<script>\s*document\.addEventListener\('contextmenu'.*?</script>)",
        original_html, re.DOTALL
    )
    security_script = security_match.group(1) if security_match else ''

    salt_b64 = encrypted_data['salt']
    iv_b64 = encrypted_data['iv']
    data_b64 = encrypted_data['data']

    # Variable values inserted via f-string don't need brace escaping
    lock_screen_safe = lock_screen_html
    step_scripts_safe = step_scripts
    security_script_safe = security_script

    return f'''<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BABAK 2026</title>
    <script src="https://cdn.tailwindcss.com"></script>
    {tw_config}
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Playfair+Display:ital,wght@0,400;0,600;0,700;0,800;0,900;1,400;1,700&display=swap" rel="stylesheet">
    <style>{styles}</style>
</head>
<body class="bg-black">

    {security_script_safe}

    <!-- CRT Monitor Wrapper (Desktop only) -->
    <div id="crt-monitor">
    <div id="crt-screen">

    {lock_screen_safe}

    <!-- Encrypted content container -->
    <div id="decrypted-content"></div>

    {step_scripts_safe}

    <script>
    (function() {{
        'use strict';

        const ENCRYPTED_DATA = {{
            salt: '{salt_b64}',
            iv: '{iv_b64}',
            data: '{data_b64}'
        }};

        // Particle system for lock screen
        function createLockParticles() {{
            const container = document.getElementById('lock-particles');
            if (!container) return;
            for (let i = 0; i < 40; i++) {{
                const p = document.createElement('div');
                const isStar = Math.random() > 0.6;
                const size = isStar ? (Math.random() * 8 + 4) : (Math.random() * 4 + 2);
                p.className = 'particle ' + (isStar ? 'particle-star' : 'particle-gold');
                p.style.cssText = 'width:' + size + 'px;height:' + size + 'px;left:' + (Math.random()*100) + '%;animation:fall ' + (Math.random()*8+6) + 's linear infinite;animation-delay:' + (Math.random()*10) + 's;';
                container.appendChild(p);
            }}
        }}
        createLockParticles();

        const pwInput = document.getElementById('password-input');
        const enterBtn = document.getElementById('enter-btn');
        const errorMsg = document.getElementById('error-msg');

        if (!enterBtn) return;

        async function decrypt(password) {{
            const enc = new TextEncoder();
            const saltBytes = Uint8Array.from(atob(ENCRYPTED_DATA.salt), c => c.charCodeAt(0));
            const combined = Uint8Array.from(atob(ENCRYPTED_DATA.data), c => c.charCodeAt(0));

            const keyMaterial = await crypto.subtle.importKey(
                'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
            );

            const key = await crypto.subtle.deriveKey(
                {{ name: 'PBKDF2', salt: saltBytes, iterations: 100000, hash: 'SHA-256' }},
                keyMaterial,
                {{ name: 'AES-GCM', length: 256 }},
                false,
                ['decrypt']
            );

            const iv = combined.slice(0, 12);
            const ciphertext = combined.slice(12);

            const decrypted = await crypto.subtle.decrypt(
                {{ name: 'AES-GCM', iv: iv }},
                key,
                ciphertext
            );

            return new TextDecoder().decode(decrypted);
        }}

        async function tryUnlock() {{
            const pw = pwInput.value;
            if (!pw) return;

            try {{
                const html = await decrypt(pw);

                const lockScreen = document.getElementById('lock-screen');
                lockScreen.style.transition = 'opacity 0.8s ease, transform 0.8s ease';
                lockScreen.style.opacity = '0';
                lockScreen.style.transform = 'scale(1.05)';

                setTimeout(() => {{
                    lockScreen.remove();
                    document.getElementById('decrypted-content').innerHTML = html;

                    const scripts = document.getElementById('decrypted-content').querySelectorAll('script');
                    scripts.forEach(oldScript => {{
                        const newScript = document.createElement('script');
                        if (oldScript.src) {{
                            newScript.src = oldScript.src;
                        }} else {{
                            newScript.textContent = oldScript.textContent;
                        }}
                        oldScript.parentNode.replaceChild(newScript, oldScript);
                    }});
                }}, 800);
            }} catch (e) {{
                pwInput.classList.add('shake');
                errorMsg.style.opacity = '1';
                pwInput.style.borderColor = 'rgba(239, 68, 68, 0.5)';

                setTimeout(() => {{
                    pwInput.classList.remove('shake');
                    pwInput.style.borderColor = 'rgba(255, 215, 0, 0.3)';
                }}, 600);
                setTimeout(() => {{ errorMsg.style.opacity = '0'; }}, 3000);
            }}
        }}

        enterBtn.addEventListener('click', tryUnlock);
        pwInput.addEventListener('keydown', e => {{ if (e.key === 'Enter') tryUnlock(); }});
    }})();
    </script>

    </div><!-- #crt-screen -->
    <div id="crt-off-overlay"></div>
    <div id="crt-frame"></div>
    <div id="crt-scanlines"></div>
    <button id="crt-power"></button>
    </div><!-- #crt-monitor -->

    <script>
    (function() {{
        var crtPower = document.getElementById('crt-power');
        var crtOff = document.getElementById('crt-off-overlay');
        var crtFrame = document.getElementById('crt-frame');
        var crtScanlines = document.getElementById('crt-scanlines');
        if (crtPower && window.innerWidth >= 1024) {{
            var crtIsOn = true;
            crtPower.addEventListener('click', function() {{
                crtIsOn = !crtIsOn;
                crtOff.classList.toggle('off', !crtIsOn);
                crtFrame.classList.toggle('off', !crtIsOn);
                if (crtScanlines) crtScanlines.style.display = crtIsOn ? '' : 'none';
            }});
        }}
    }})();
    </script>
</body>
</html>'''


def main():
    print("🔐 Building encrypted page...")

    # Read the dev.html
    html_content = INPUT_FILE.read_text(encoding='utf-8')

    # Extract the content that should be encrypted (everything inside main-content + scripts)
    import re

    # We need to extract:
    # 1. The main content div (without lock screen)
    # 2. The initialization scripts

    # Get main-content div
    main_match = re.search(
        r'(<div id="main-content".*?)(<!-- ={40,} -->\s*<!-- JAVASCRIPT -->.*?</script>)',
        html_content, re.DOTALL
    )

    if not main_match:
        # Fallback: extract everything between main-content markers
        start = html_content.find('<div id="main-content"')
        end = html_content.rfind('</script>') + len('</script>')
        if start == -1:
            raise ValueError("Could not find main-content in dev.html")
        content_to_encrypt = html_content[start:end]
    else:
        content_to_encrypt = main_match.group(1) + main_match.group(2)

    # Actually, let's take a cleaner approach: extract everything between
    # <!-- MAIN CONTENT --> and the closing </body>
    start_marker = '<!-- MAIN CONTENT (hidden until unlocked) -->'
    end_marker = '<!-- ============================================ -->\n    <!-- JAVASCRIPT -->'

    # Simpler: get the main-content div and the script
    main_start = html_content.find('<div id="main-content"')
    script_end = html_content.rfind('</script>')

    if main_start == -1 or script_end == -1:
        raise ValueError("Could not parse dev.html structure")

    # Include everything from main-content to the last </script>
    content_to_encrypt = html_content[main_start:script_end + len('</script>')]

    # Remove the 'hidden' class so content is visible after decryption
    content_to_encrypt = content_to_encrypt.replace(
        '<div id="main-content" class="hidden">',
        '<div id="main-content">'
    )

    print(f"  Content size: {len(content_to_encrypt):,} bytes")

    # Encrypt
    plaintext_bytes = content_to_encrypt.encode('utf-8')
    encrypted = encrypt_webcrypto_compatible(plaintext_bytes, PASSWORD)

    print(f"  Encrypted size: {len(encrypted['data']):,} bytes (base64)")

    # Build output page
    output_html = build_encrypted_page(encrypted, html_content)

    # Fix escaped characters
    output_html = output_html.replace('\\u00f6', 'ö')
    output_html = output_html.replace('\\u266a', '♪')
    output_html = output_html.replace("\\\\'", "\\'")

    OUTPUT_FILE.write_text(output_html, encoding='utf-8')
    print(f"  Output: {OUTPUT_FILE}")
    print(f"  Output size: {len(output_html):,} bytes")
    print("✅ Done! index.html is ready for deployment.")


if __name__ == '__main__':
    main()
