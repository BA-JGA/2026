#!/usr/bin/env node
/**
 * Build script: Encrypts page content with AES-256-GCM
 * Compatible with Web Crypto API decryption in browser.
 * Password is NEVER stored — only used as encryption key.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PASSWORD = 'Iranazadi';
const INPUT_FILE = path.join(__dirname, 'dev.html');
const OUTPUT_FILE = path.join(__dirname, 'index.html');
const ITERATIONS = 100000;

function encrypt(plaintext, password) {
    const salt = crypto.randomBytes(16);
    const iv = crypto.randomBytes(12);

    // PBKDF2 key derivation (matches Web Crypto API)
    const key = crypto.pbkdf2Sync(password, salt, ITERATIONS, 32, 'sha256');

    // AES-256-GCM encryption
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();

    // Combined format: iv (12) + ciphertext + tag (16) — matches Web Crypto API
    const combined = Buffer.concat([iv, encrypted, tag]);

    return {
        salt: salt.toString('base64'),
        iv: iv.toString('base64'),
        data: combined.toString('base64')
    };
}

function buildEncryptedPage(encData, originalHtml) {
    // Extract styles from original
    const styleMatch = originalHtml.match(/<style>([\s\S]*?)<\/style>/);
    const styles = styleMatch ? styleMatch[1] : '';

    // Extract tailwind config
    const twMatch = originalHtml.match(/tailwind\.config\s*=\s*(\{[\s\S]*?\})\s*\n\s*<\/script>/);
    const twConfig = twMatch ? twMatch[1] : '{}';

    return `<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BABAK 2026</title>
    <meta name="robots" content="noindex, nofollow">
    <script src="https://cdn.tailwindcss.com"></script>
    <script>tailwind.config = ${twConfig}</script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Playfair+Display:ital,wght@0,400;0,600;0,700;0,800;0,900;1,400;1,700&display=swap" rel="stylesheet">
    <style>${styles}</style>
</head>
<body class="bg-black text-white" style="font-family:'Inter',system-ui,sans-serif;">

    <!-- Lock Screen (visible) -->
    <div id="lock-screen" class="fixed inset-0 z-50 flex flex-col items-center justify-center bg-black">
        <div id="lock-particles" class="fixed inset-0 pointer-events-none overflow-hidden"></div>
        <div class="relative z-10 flex flex-col items-center px-6 text-center" style="animation: fadeIn 1.5s ease-out">
            <svg width="80" height="50" viewBox="0 0 80 50" class="mb-8 opacity-60" style="animation: float 4s ease-in-out infinite">
                <ellipse cx="40" cy="42" rx="40" ry="8" fill="#FFD700" opacity="0.8"/>
                <ellipse cx="40" cy="38" rx="28" ry="20" fill="#1a1a1a" stroke="#FFD700" stroke-width="1.5"/>
                <path d="M12 38 Q40 10 68 38" fill="#1a1a1a" stroke="#FFD700" stroke-width="1"/>
                <rect x="28" y="22" width="24" height="6" rx="2" fill="#FFD700" opacity="0.6"/>
            </svg>
            <h1 class="font-display text-3xl sm:text-4xl md:text-5xl font-bold mb-4 text-gold-gradient">The Show Must Go On</h1>
            <p class="text-white/50 text-sm sm:text-base md:text-lg mb-2 max-w-md leading-relaxed" style="animation: fadeInUp 1.5s ease-out 0.3s both">
                Wenn du diese Seite betrittst,<br>bist du bereits Teil von
            </p>
            <p class="text-gold-gradient font-display text-2xl sm:text-3xl font-bold mb-10" style="animation: fadeInUp 1.5s ease-out 0.5s both">Babaks Scheidung</p>
            <p class="text-white/20 text-xs mb-8 max-w-xs" style="animation: fadeInUp 1.5s ease-out 0.7s both">* Vom Junggesellenleben. Kein Anwalt n\u00f6tig. Vielleicht.</p>
            <div class="relative" style="animation: fadeInUp 1.5s ease-out 0.9s both">
                <input type="password" id="password-input" class="lock-input" placeholder="Passwort" autocomplete="off" spellcheck="false">
                <p id="error-msg" class="text-red-400 text-sm mt-3 opacity-0 transition-opacity duration-300">Wrong key, Smooth Criminal. Versuch's nochmal.</p>
            </div>
            <button id="enter-btn" class="btn-gold mt-6 text-sm tracking-wider uppercase" style="animation: fadeInUp 1.5s ease-out 1.1s both">Eintreten</button>
            <p class="text-white/10 text-xs mt-12" style="animation: fadeIn 2s ease-out 2s both">\u266a Just Beat It... oder gib das richtige Passwort ein \u266a</p>
        </div>
    </div>

    <!-- Decrypted content injected here -->
    <div id="decrypted-content"></div>

    <script>
    (function() {
        'use strict';

        var ED = {
            salt: '${encData.salt}',
            data: '${encData.data}'
        };

        // Lock screen particles
        (function() {
            var c = document.getElementById('lock-particles');
            for (var i = 0; i < 40; i++) {
                var p = document.createElement('div');
                var star = Math.random() > 0.6;
                var sz = star ? (Math.random()*8+4) : (Math.random()*4+2);
                p.className = 'particle ' + (star ? 'particle-star' : 'particle-gold');
                p.style.cssText = 'width:'+sz+'px;height:'+sz+'px;left:'+(Math.random()*100)+'%;animation:fall '+(Math.random()*8+6)+'s linear infinite;animation-delay:'+(Math.random()*10)+'s;';
                c.appendChild(p);
            }
        })();

        function b64ToBytes(b64) {
            var bin = atob(b64);
            var bytes = new Uint8Array(bin.length);
            for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
            return bytes;
        }

        async function decrypt(password) {
            var enc = new TextEncoder();
            var saltBytes = b64ToBytes(ED.salt);
            var combined = b64ToBytes(ED.data);

            var keyMaterial = await crypto.subtle.importKey(
                'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
            );

            var key = await crypto.subtle.deriveKey(
                { name: 'PBKDF2', salt: saltBytes, iterations: ${ITERATIONS}, hash: 'SHA-256' },
                keyMaterial,
                { name: 'AES-GCM', length: 256 },
                false,
                ['decrypt']
            );

            var iv = combined.slice(0, 12);
            var ciphertext = combined.slice(12);

            var decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: iv },
                key,
                ciphertext
            );

            return new TextDecoder().decode(decrypted);
        }

        var pwInput = document.getElementById('password-input');
        var enterBtn = document.getElementById('enter-btn');
        var errorMsg = document.getElementById('error-msg');

        async function tryUnlock() {
            var pw = pwInput.value;
            if (!pw) return;

            enterBtn.disabled = true;
            enterBtn.textContent = '...';

            try {
                var html = await decrypt(pw);

                var ls = document.getElementById('lock-screen');
                ls.style.transition = 'opacity 0.8s ease, transform 0.8s ease';
                ls.style.opacity = '0';
                ls.style.transform = 'scale(1.05)';

                setTimeout(function() {
                    ls.remove();
                    var container = document.getElementById('decrypted-content');
                    container.innerHTML = html;

                    // Execute scripts in decrypted content
                    var scripts = container.querySelectorAll('script');
                    scripts.forEach(function(old) {
                        var s = document.createElement('script');
                        if (old.src) { s.src = old.src; }
                        else { s.textContent = old.textContent; }
                        old.parentNode.replaceChild(s, old);
                    });
                }, 800);
            } catch(e) {
                pwInput.classList.add('shake');
                errorMsg.style.opacity = '1';
                pwInput.style.borderColor = 'rgba(239,68,68,0.5)';

                setTimeout(function() {
                    pwInput.classList.remove('shake');
                    pwInput.style.borderColor = 'rgba(255,215,0,0.3)';
                }, 600);
                setTimeout(function() { errorMsg.style.opacity = '0'; }, 3000);

                enterBtn.disabled = false;
                enterBtn.textContent = 'EINTRETEN';
            }
        }

        enterBtn.addEventListener('click', tryUnlock);
        pwInput.addEventListener('keydown', function(e) { if (e.key === 'Enter') tryUnlock(); });
        setTimeout(function() { pwInput.focus(); }, 500);
    })();
    </script>
</body>
</html>`;
}

// ---- Main ----
console.log('🔐 Building encrypted page...');

const html = fs.readFileSync(INPUT_FILE, 'utf-8');

// Extract main content (everything from <div id="main-content" to last </script>)
const mainStart = html.indexOf('<div id="main-content"');
const lastScript = html.lastIndexOf('</script>');

if (mainStart === -1 || lastScript === -1) {
    console.error('❌ Could not find main-content in dev.html');
    process.exit(1);
}

let contentToEncrypt = html.substring(mainStart, lastScript + '</script>'.length);

// Remove 'hidden' class so content shows after decryption
contentToEncrypt = contentToEncrypt.replace(
    '<div id="main-content" class="hidden">',
    '<div id="main-content">'
);

console.log(`  Content: ${contentToEncrypt.length.toLocaleString()} bytes`);

// Encrypt
const encrypted = encrypt(contentToEncrypt, PASSWORD);
console.log(`  Encrypted: ${encrypted.data.length.toLocaleString()} bytes (base64)`);

// Build output
const output = buildEncryptedPage(encrypted, html);
fs.writeFileSync(OUTPUT_FILE, output, 'utf-8');

console.log(`  Output: ${OUTPUT_FILE}`);
console.log(`  Size: ${output.length.toLocaleString()} bytes`);
console.log('✅ Done! index.html is ready for deployment.');
